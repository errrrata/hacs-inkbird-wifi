"""Switch platform — gateway feature toggles.

Currently empty for the IM-03-W: the bool DPs the gateway exposes (128, 132,
133, 134, 136) correspond to features like Buzzer / Backlight Always On /
12-hour clock / Temperature reminder / Humidity reminder, but the exact
DP-to-feature mapping is still being reverse-engineered. New switches will
be enabled here once each DP is confirmed against the Inkbird app.

To map a feature: toggle it in the Inkbird app, then look at the `dps`
attribute of `sensor.<device>_diagnostics` in Home Assistant — the bool
value that flipped is the matching DP.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import InkbirdWifiCoordinator


# Iterable of (label, dp_attr_name) pairs to spawn one SwitchEntity each
# when the product spec declares that DP. As we confirm DP↔feature mappings,
# add the corresponding spec field to PRODUCTS and an entry here.
_SWITCHES: tuple[tuple[str, str], ...] = (
    ("Buzzer", "buzzer_dp"),
    ("Backlight always on", "backlight_dp"),
    ("12-hour clock", "hour_mode_dp"),
    ("Temperature alarm", "temp_reminder_dp"),
    ("Humidity alarm", "humi_reminder_dp"),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator: InkbirdWifiCoordinator = entry.runtime_data
    entities: list[SwitchEntity] = []
    for label, attr in _SWITCHES:
        dp = getattr(coordinator.spec, attr, None)
        if dp:
            entities.append(BoolDpSwitch(coordinator, entry, label, attr, dp))
    if entities:
        async_add_entities(entities)


class BoolDpSwitch(CoordinatorEntity[InkbirdWifiCoordinator], SwitchEntity):
    """Generic on/off mirror of one boolean DP."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: InkbirdWifiCoordinator,
        entry: ConfigEntry,
        label: str,
        attr_name: str,
        dp: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_device_info = coordinator.device_info
        self._attr_name = label
        self._attr_unique_id = f"{entry.entry_id}_{attr_name}"
        self._dp = dp

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data
        if not data or self._dp not in data.dps:
            return None
        return bool(data.dps[self._dp])

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.write_dp(self._dp, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.write_dp(self._dp, False)
