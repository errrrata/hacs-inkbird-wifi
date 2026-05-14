"""Per-product decoders for the inkbird_wifi integration.

Each Inkbird WiFi device on the Tuya backend has a Tuya `productId` (e.g.
`vftsypplefmoy4uc` for the IM-03-W gateway). The DP layout — which DPs hold
sensor data, what binary structure the cloud blob has, what DP triggers a
fresh scan — is specific to that product. To support a new device:

  1. Capture its `productId` from your Inkbird app account (it's logged by
     the config flow when the device is unsupported).
  2. Reverse-engineer the DP layout (see findings.md for how the IM-03-W's
     was cracked) and write a `decode_*` function returning a list of
     `SensorReading`.
  3. Add a `ProductSpec` entry to `PRODUCTS` below.

The rest of the integration (auth, discovery, LAN/cloud transport) is
product-agnostic.
"""
from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class SensorReading:
    name: str
    temperature: float | None
    humidity: float | None
    battery: int | None = None     # 0-100 if known, else None


@dataclass(frozen=True)
class CoordinatorData:
    """One refresh result: decoded sub-sensor readings + raw current DPs.

    `dps` is the raw dict from the device (LAN status or cloud `tuya.m.device.get`)
    so entities for control DPs (temp-unit select, hour-mode switch, gateway
    battery sensor) can show the current state. May be empty if the device
    only emitted the sensor-data DP.
    """

    readings: list[SensorReading]
    dps: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.readings) or bool(self.dps)


@dataclass(frozen=True)
class ProductSpec:
    """Everything needed to talk to one model of Inkbird WiFi device."""

    product_id: str                          # Tuya `productId` returned by the cloud
    model: str                               # Human-readable model (HA device_info.model)
    current_data_dp: str                     # DP that holds the latest sensor blob
    scan_trigger_dp: str | None              # DP to write True to force a scan (None = no trigger)
    decoder: Callable[[str], list[SensorReading]]
    # Writable controls (set to None when the product doesn't expose this control)
    temp_unit_dp: str | None = None          # DP that holds the temp unit ('c' / 'f')
    battery_dp: str | None = None            # DP that reports gateway battery level (0-3)
    # Mappings below are still being reverse-engineered (the gateway exposes
    # several bool DPs — 128, 132, 133, 134, 136 — for features like buzzer,
    # backlight, hour-mode, temp/humidity reminders. None of them are confirmed
    # yet; left as None until verified against the running app).
    buzzer_dp: str | None = None
    backlight_dp: str | None = None
    hour_mode_dp: str | None = None
    temp_reminder_dp: str | None = None
    humi_reminder_dp: str | None = None


# ------------------------------------------------------------------
# IM-03-W (gateway with up to 5 paired IBS-P03R BLE temp/humidity probes)
# ------------------------------------------------------------------

# DP 102 = base64-encoded array of 51-byte records (one per slot).
# Layout per record:
#   byte 0       : validity flag (0x00/0xff = empty slot)
#   bytes 9..10  : temperature, little-endian int16, /10 -> °C (0x7FFF = no probe)
#   bytes 11..12 : humidity,   little-endian uint16, /10 -> %  (0 or 0xFFFF = no humidity)
#   byte 29      : sub-sensor battery percentage (0..100, confirmed 2026-05-12)
#   bytes 36..50 : sensor name, null-terminated ASCII (e.g. "P03R_IN", "P03R_OUT")
_IM03W_RECORD_SIZE = 51
_IM03W_TEMP_OFFSET = 9
_IM03W_HUMI_OFFSET = 11
_IM03W_BATT_OFFSET = 29
_IM03W_NAME_OFFSET = 36


def _decode_im03w(raw_b64: str) -> list[SensorReading]:
    try:
        data = base64.b64decode(raw_b64)
    except Exception:
        return []

    readings: list[SensorReading] = []
    for i in range(len(data) // _IM03W_RECORD_SIZE):
        chunk = data[i * _IM03W_RECORD_SIZE : (i + 1) * _IM03W_RECORD_SIZE]
        if len(chunk) < _IM03W_NAME_OFFSET + 1:
            continue
        if chunk[0] == 0x00 or all(b == 0xFF for b in chunk[1:8]):
            continue

        batt_raw = chunk[_IM03W_BATT_OFFSET]
        temp_raw = struct.unpack_from("<h", chunk, _IM03W_TEMP_OFFSET)[0]
        humi_raw = struct.unpack_from("<H", chunk, _IM03W_HUMI_OFFSET)[0]

        battery = batt_raw if 0 <= batt_raw <= 100 else None
        temp = round(temp_raw / 10.0, 1) if temp_raw != 0x7FFF else None
        humi = round(humi_raw / 10.0, 1) if humi_raw not in (0, 0xFFFF) else None

        name_bytes = chunk[_IM03W_NAME_OFFSET:]
        name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace").strip()
        if not name:
            name = f"sensor_{i + 1}"

        readings.append(SensorReading(
            name=name, temperature=temp, humidity=humi, battery=battery,
        ))
    return readings


# ------------------------------------------------------------------
# Registry — add new products here.
# Key = Tuya `productId` string from the device record.
# ------------------------------------------------------------------

PRODUCTS: dict[str, ProductSpec] = {
    "vftsypplefmoy4uc": ProductSpec(
        product_id="vftsypplefmoy4uc",
        model="IM-03-W",
        current_data_dp="102",
        scan_trigger_dp="129",
        decoder=_decode_im03w,
        temp_unit_dp="9",     # "c" / "f"  (confirmed)
        battery_dp="131",     # 0-3        (confirmed)
        # buzzer_dp / backlight_dp / hour_mode_dp / temp_reminder_dp / humi_reminder_dp
        # not yet confirmed — the raw bool DPs (128/132/133/134/136) need to be
        # mapped by toggling each feature in the Inkbird app one at a time.
    ),
}


def get_product(product_id: str) -> ProductSpec | None:
    return PRODUCTS.get(product_id)


def is_supported(product_id: str) -> bool:
    return product_id in PRODUCTS
