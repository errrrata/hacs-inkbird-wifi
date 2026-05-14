# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

HACS-installable Home Assistant integration for the **Inkbird IM-03-W WiFi gateway**. Users authenticate with their Inkbird app credentials (email/password or Google) and the integration auto-discovers their gateway and paired BLE sub-sensors via Tuya cloud, then prefers a direct LAN connection at runtime with cloud as a fallback.

## Repo layout

```
.
├── README.md                          # User-facing docs (also rendered by HACS)
├── hacs.json                          # HACS metadata
├── deploy.sh                          # Local-dev rsync to /data/homeassistant/...
├── CLAUDE.md                          # This file
├── findings.md                        # Reverse-engineering notes (gitignored — protocol details)
├── tuya_sign.py                       # Standalone Python reference (gitignored — dev tool)
└── custom_components/inkbird_wifi/    # The integration
    ├── manifest.json                  # version, requirements, codeowner, HACS metadata
    ├── __init__.py                    # entry setup
    ├── const.py                       # entry data keys + DP constants + record layout
    ├── tuya_cloud.py                  # Async Tuya cloud client (sign, encrypt, login flows)
    ├── coordinator.py                 # LAN-first / cloud-fallback DataUpdateCoordinator
    ├── config_flow.py                 # Two paths: email+password OR Google sub
    ├── sensor.py                      # SensorEntity classes (temp + humidity)
    ├── strings.json                   # UI labels
    └── translations/en.json           # synced from strings.json
```

The `inkbird*.apk`, `inkbird*_decoded/`, `inkbird*_java/`, `thingsmart_extracted/`, and other large reverse-engineering artifacts live at the repo root but are gitignored. They're the inputs to the research notes in `findings.md`.

## Local development cycle

```bash
# Edit files under custom_components/inkbird_wifi/
./deploy.sh                            # rsyncs to /data/homeassistant/.../custom_components/inkbird_wifi/
docker restart homeassistant           # (or use HA's Reload integration if only config changes)
docker logs --since 2m homeassistant | grep -i inkbird_wifi
```

The integration is wired to load with `custom_components.inkbird_wifi: debug` in the HA logger config, so coordinator + cloud round-trips are visible in the journal.

## Standalone reference: `tuya_sign.py`

`tuya_sign.py` at the repo root is the pure-Python (urllib) reference companion to `custom_components/inkbird_wifi/tuya_cloud.py` (aiohttp). Both implement the same wire protocol. The standalone is useful for:

- Running self-tests outside HA (`python3 tuya_sign.py` — exercises 8 captured AES-key oracle pairs + a live US round-trip).
- Quick experiments / probing endpoints from the CLI.
- Showing the protocol cleanly without HA abstractions getting in the way.

Keep `tuya_sign.py` and `tuya_cloud.py` semantically equivalent on the crypto + login flow. If you change one, update the other.

## Protocol cheat sheet

See `findings.md` for the comprehensive version. Quick reference:

- **Sign:** `HMAC-SHA256(SIGN_KEY, sorted_joined_params)`
- **postData:** AES-128-GCM, base64(nonce(12) || ct || tag(16)), AAD=null. Key = `HMAC-SHA256(rid, SIGN_KEY).hex()[:16]` ASCII bytes (when `ecode=None`).
- **Login bridge:** INKBIRD `/smartAgent/user/login` with `thirdUid=google_sub` (no idToken validation — see Security & privacy in README) → derive Tuya uid `"1_"+sub` → `smartlife.m.user.username.token.get` v2.0 → RSA-encrypt `md5(TUYA_OEM_PASSWORD).hex()` → `smartlife.m.user.uid.password.login.reg` v1.0.
- **Device list:** `tuya.m.my.group.device.list` v1.0 with `gid` as unsigned query param.
- **Cloud DP read:** `tuya.m.device.get` v1.0 with `{devId}` — returns the same DP 102 blob as LAN.

## Versioning

Bump `manifest.json` `version` for every release. HACS uses semver tags on the repo to drive update notifications, so tag releases as `vX.Y.Z` to match.

## Things to be careful about

- **Don't print/log raw idTokens or `sub` values at INFO/WARNING level.** Debug-level is fine.
- **Don't bake real device IDs / local keys into the test scripts.** Use values from the bad@nod.cc test account or document them as "captured from emulator" only.
- **Coordinator path stickiness:** once "cloud" or "lan" succeeds, the other path is only tried when the sticky one fails. If you're testing a code change to one path, you may need to restart HA to clear the preference.
