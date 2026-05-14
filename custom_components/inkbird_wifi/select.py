"""Select platform — gateway temperature-unit toggle (°C / °F)."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import InkbirdWifiCoordinator


_TEMP_UNIT_OPTIONS = ["Celsius", "Fahrenheit"]
_TEMP_UNIT_TO_DP = {"Celsius": "c", "Fahrenheit": "f"}
_TEMP_UNIT_FROM_DP = {v: k for k, v in _TEMP_UNIT_TO_DP.items()}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator: InkbirdWifiCoordinator = entry.runtime_data
    if coordinator.spec.temp_unit_dp:
        async_add_entities([TempUnitSelect(coordinator, entry)])


class TempUnitSelect(CoordinatorEntity[InkbirdWifiCoordinator], SelectEntity):
    """Mirrors the gateway's DP 9 (temperature unit)."""

    _attr_has_entity_name = True
    _attr_name = "Temperature unit"
    _attr_options = _TEMP_UNIT_OPTIONS

    def __init__(self, coordinator: InkbirdWifiCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_device_info = coordinator.device_info
        self._attr_unique_id = f"{entry.entry_id}_temp_unit"

    @property
    def current_option(self) -> str | None:
        data = self.coordinator.data
        dp = self.coordinator.spec.temp_unit_dp
        if not data or dp is None:
            return None
        raw = str(data.dps.get(dp, "")).lower()
        return _TEMP_UNIT_FROM_DP.get(raw)

    async def async_select_option(self, option: str) -> None:
        value = _TEMP_UNIT_TO_DP.get(option)
        if value is None:
            return
        dp = self.coordinator.spec.temp_unit_dp
        if dp is None:
            return
        await self.coordinator.write_dp(dp, value)
