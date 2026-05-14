"""Button platform — manual scan trigger for the IM-03-W gateway."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import InkbirdWifiCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator: InkbirdWifiCoordinator = entry.runtime_data
    if coordinator.spec.scan_trigger_dp:
        async_add_entities([ScanTriggerButton(coordinator, entry)])


class ScanTriggerButton(CoordinatorEntity[InkbirdWifiCoordinator], ButtonEntity):
    """Pressing this sends DP 129=True to make the gateway poll its sub-sensors now."""

    _attr_has_entity_name = True
    _attr_name = "Scan sub-sensors"

    def __init__(self, coordinator: InkbirdWifiCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_device_info = coordinator.device_info
        self._attr_unique_id = f"{entry.entry_id}_scan_trigger"

    async def async_press(self) -> None:
        dp = self.coordinator.spec.scan_trigger_dp
        if dp is None:
            return
        await self.coordinator.write_dp(dp, True)
