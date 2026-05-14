"""Sensor platform for Inkbird Wifi devices.

Uses a `SENSOR_DESCRIPTIONS` registry (pattern borrowed from HA's built-in
`inkbird` BLE integration) so each measurement type is described once and
the same `InkbirdSensor` class drives all of them. Adding a new measurement
(battery, CO2, pressure, …) is a one-row change to the registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

import logging

from .const import DOMAIN
from .coordinator import InkbirdWifiCoordinator
from .products import SensorReading

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class InkbirdSensorEntityDescription(SensorEntityDescription):
    """SensorEntityDescription that knows how to pull its value out of a SensorReading."""

    value_fn: Callable[[SensorReading], float | None]


# Registry of every measurement type a paired sub-sensor can expose.
# Add new entries as new product decoders surface new fields.
SENSOR_DESCRIPTIONS: tuple[InkbirdSensorEntityDescription, ...] = (
    InkbirdSensorEntityDescription(
        key="temperature",
        translation_key="temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda r: r.temperature,
    ),
    InkbirdSensorEntityDescription(
        key="humidity",
        translation_key="humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda r: r.humidity,
    ),
    InkbirdSensorEntityDescription(
        key="battery",
        translation_key="battery",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda r: r.battery,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one entity per (sub-sensor, measurement-with-data) pair as they're discovered."""
    coordinator: InkbirdWifiCoordinator = entry.runtime_data
    known: set[tuple[str, str]] = set()  # (sensor_name, description.key)

    gateway_added = False

    @callback
    def _add_new() -> None:
        nonlocal gateway_added
        data = coordinator.data
        readings = data.readings if data else []
        new: list[SensorEntity] = []
        for reading in readings:
            for desc in SENSOR_DESCRIPTIONS:
                if desc.value_fn(reading) is None:
                    continue
                key = (reading.name, desc.key)
                if key in known:
                    continue
                known.add(key)
                new.append(InkbirdSensor(coordinator, entry, reading.name, desc))
        if not gateway_added:
            if coordinator.spec.battery_dp:
                new.append(GatewayBatterySensor(coordinator, entry))
            new.append(RawDpsDiagnostic(coordinator, entry))
            gateway_added = True
        if new:
            _LOGGER.debug("Adding %d new entities", len(new))
            async_add_entities(new)

    entry.async_on_unload(coordinator.async_add_listener(_add_new))
    _add_new()


class InkbirdSensor(CoordinatorEntity[InkbirdWifiCoordinator], SensorEntity):
    """Single measurement (temperature / humidity / …) for one sub-sensor."""

    entity_description: InkbirdSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: InkbirdWifiCoordinator,
        entry: ConfigEntry,
        sensor_name: str,
        description: InkbirdSensorEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._sensor_name = sensor_name
        self._attr_device_info = coordinator.device_info
        self._attr_unique_id = f"{entry.entry_id}_{sensor_name}_{description.key}"
        self._attr_name = f"{sensor_name} {description.key.capitalize()}"

    @property
    def native_value(self) -> float | None:
        data = self.coordinator.data
        if not data:
            return None
        for r in data.readings:
            if r.name == self._sensor_name:
                return self.entity_description.value_fn(r)
        return None


class GatewayBatterySensor(CoordinatorEntity[InkbirdWifiCoordinator], SensorEntity):
    """Gateway-side battery level (0–3 scaled to %)."""

    _attr_has_entity_name = True
    _attr_name = "Gateway battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: InkbirdWifiCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_device_info = coordinator.device_info
        self._attr_unique_id = f"{entry.entry_id}_gateway_battery"

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data
        if not data:
            return None
        dp = self.coordinator.spec.battery_dp
        if dp is None or dp not in data.dps:
            return None
        try:
            raw = int(data.dps[dp])
        except (TypeError, ValueError):
            return None
        # DP 131 reports 0..3 — scale linearly to 0/33/66/100 %.
        return max(0, min(3, raw)) * 100 // 3


class RawDpsDiagnostic(CoordinatorEntity[InkbirdWifiCoordinator], SensorEntity):
    """Diagnostic sensor exposing the gateway's full raw DP dict as attributes.

    Use this while reverse-engineering: toggle a feature in the Inkbird app,
    refresh the integration, and compare attributes here against the previous
    snapshot — the DP that flipped is the one bound to that feature.
    """

    _attr_has_entity_name = True
    _attr_name = "Diagnostics"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False  # off by default; user enables when mapping

    def __init__(self, coordinator: InkbirdWifiCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_device_info = coordinator.device_info
        self._attr_unique_id = f"{entry.entry_id}_diagnostics"

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data
        return len(data.dps) if data else None

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        data = self.coordinator.data
        if not data:
            return {}
        # Hide DP 102 — it's the big sensor blob, not useful as an attribute.
        return {f"dp_{k}": v for k, v in sorted(data.dps.items()) if k != "102"}
