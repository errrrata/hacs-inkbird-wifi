"""Inkbird Wifi integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_EMAIL,
    CONF_GOOGLE_SUB,
    CONF_HOST,
    CONF_LOCAL_KEY,
    CONF_PASSWORD,
    CONF_PRODUCT_ID,
    CONF_REGION,
    CONF_VERSION,
    DEFAULT_VERSION,
)
from .coordinator import InkbirdWifiCoordinator
from .products import get_product
from .tuya_cloud import DEFAULT_REGION

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR, Platform.BUTTON, Platform.SELECT, Platform.SWITCH]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    product_id = entry.data.get(CONF_PRODUCT_ID, "")
    spec = get_product(product_id)
    if spec is None:
        if not product_id:
            # Entry predates the product registry — assume IM-03-W (the only
            # product supported before this refactor) so existing setups keep
            # working without forcing the user to re-add.
            spec = get_product("vftsypplefmoy4uc")
            _LOGGER.info(
                "Entry %s has no product_id stored; defaulting to IM-03-W. "
                "Remove + re-add the integration to refresh entry data.",
                entry.title,
            )
        else:
            _LOGGER.error(
                "Unsupported Tuya productId %r for entry %s — please open a "
                "GitHub issue with this productId so we can add a decoder.",
                product_id, entry.title,
            )
            raise ConfigEntryNotReady(f"Unsupported product {product_id!r}")

    coordinator = InkbirdWifiCoordinator(
        hass,
        entry=entry,
        spec=spec,
        device_id=entry.data[CONF_DEVICE_ID],
        host=entry.data.get(CONF_HOST, ""),
        local_key=entry.data.get(CONF_LOCAL_KEY, ""),
        version=entry.data.get(CONF_VERSION, DEFAULT_VERSION),
        email=entry.data.get(CONF_EMAIL, ""),
        google_sub=entry.data.get(CONF_GOOGLE_SUB, ""),
        password=entry.data.get(CONF_PASSWORD, ""),
        region=entry.data.get(CONF_REGION, DEFAULT_REGION),
        country_code=entry.data.get(CONF_COUNTRY_CODE, "1"),
    )
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_create_background_task(
        hass, coordinator.async_refresh(), "inkbird_wifi_first_refresh"
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
