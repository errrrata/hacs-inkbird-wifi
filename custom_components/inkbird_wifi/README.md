# Inkbird Wifi — Home Assistant Custom Integration

One-click cloud-account setup for the **Inkbird IM-03-W WiFi gateway** and its paired **IBS-P03R** temperature/humidity sub-sensors. Sign in with the Inkbird app credentials you already have — no need to grab `device_id` / `local_key` by hand.

At runtime the integration prefers a **direct LAN** TCP connection (fast, no internet needed) and seamlessly falls back to **Tuya cloud polling** when the device isn't reachable on the broadcast domain (different VLAN, firewalled UDP, etc.). Whichever path works first is sticky.

## Requirements

- INKBIRD IM-03-W WiFi gateway, already paired through the INKBIRD app.
- INKBIRD app account (email + password, or Google sign-in).
- `tinytuya >= 1.13.0` and `pycryptodome` (HA already ships both).

## Installation

### HACS (recommended)

1. Open HACS → ⋮ → **Custom repositories**.
2. Add `https://github.com/errrrata/hacs-inkbird-wifi`, category **Integration**, click **ADD**.
3. Search for **Inkbird Wifi** in HACS and click **Download**.
4. Restart Home Assistant.

### Manual

Copy `custom_components/inkbird_wifi/` from this repo into your Home Assistant `config/custom_components/` directory and restart Home Assistant.

## Configuration

**Settings → Devices & Services → Add Integration → Inkbird Wifi**, then choose one of:

### Sign in with INKBIRD email + password

| Field | Description |
|-------|-------------|
| Email | Your INKBIRD account email |
| Password | Your INKBIRD account password |
| Country code | Phone country code (`1` US, `34` Spain, `44` UK, `86` China, …) |
| Region | Tuya datacenter: `us`, `eu`, `cn`, `in` |

### Sign in with Google

If your INKBIRD account was created via "Continue with Google", you don't have a password. The integration needs just your **Google account ID** (the 21-digit numeric `sub` claim from Google's OpenID identity).

**Method A — OAuth Playground, userinfo only (recommended):** never handle an idToken yourself; only the `sub` ever leaves Google's servers.

1. Open <https://developers.google.com/oauthplayground> in a browser.
2. Step 1: expand "Google OAuth2 API v2" and tick `https://www.googleapis.com/auth/userinfo.profile`.
3. Click **Authorize APIs**, sign in with the Google account you use for INKBIRD, grant consent.
4. Step 2: click **Exchange authorization code for tokens**.
5. Step 3: change the request URL field to `https://www.googleapis.com/oauth2/v2/userinfo` and click **Send the request**.
6. The response JSON contains `"id": "123456789012345678901"` — that 21-digit number is your `sub`. Copy it.
7. Paste it into HA's "Numeric Google sub" field.

**Method B — paste a full idToken** (also fine, just exposes more on screen): same steps 1–4, but copy the `id_token` field from the Step 2 response and paste the entire JWT into HA's field. The integration extracts `sub` locally with `_extract_google_sub()`, discards the rest, and never sends the idToken anywhere.

**Method C — decode an existing idToken locally:** any JWT you already have from a Google login. Paste at <https://jwt.io> (client-side, no network upload) or just split on `.` and base64url-decode the second part. Copy the `sub` field from the JSON payload.

| Field | Description |
|-------|-------------|
| Email | The email tied to your INKBIRD account |
| Numeric Google sub (or full idToken) | 21-digit `sub`, OR a full JWT we'll extract `sub` from |
| Country code | Phone country code (e.g. `1` US, `34` Spain, `44` UK, `86` China) |
| Region | Tuya datacenter: `us`, `eu`, `cn`, `in` |

### After login

The integration:
1. Calls INKBIRD's backend to look up your account (`/smartAgent/user/login`).
2. Bridges into the Tuya cloud session (`smartlife.m.user.uid.password.login.reg`, with the OEM password RSA-encrypted using a pubkey fetched at login time).
3. Lists your homes (`tuya.m.location.list`) and devices (`tuya.m.my.group.device.list`).
4. If only one IM-03-W is found, it's auto-selected; otherwise a picker appears.
5. Broadcasts on the LAN for the device's current IP (UDP 6667). If found, the LAN path is enabled and stored.
6. Creates the config entry with both LAN params (host + localKey + version) and cloud creds (email + Google sub / password + region + country code).

If the LAN broadcast scan fails (different subnet / VLAN, firewall blocking UDP), the entry is saved without `host` and the coordinator uses the cloud path on every refresh.

## Entities

For each paired IBS-P03R sub-sensor:

| Entity | Type | Unit |
|--------|------|------|
| `{sensor_name} Temperature` | `sensor` | °C |
| `{sensor_name} Humidity` | `sensor` | % (only if the sub-sensor has a humidity probe) |

New sub-sensors paired in the INKBIRD app appear in HA after the next successful poll.

## Polling behaviour

- **Interval**: every 120 seconds.
- **LAN path**: connects via tinytuya v3.4, sends DP 129 (scan trigger), waits up to 45 s for DP 102 (the aggregated 51-byte-per-sensor blob). Trigger is retried every 12 s within that window. On connection failure, broadcast-scans for the device's current LAN IP; if a new IP shows up, the config entry is updated automatically (handles DHCP renewals).
- **Cloud path**: calls `tuya.m.device.dp.publish` to ask the gateway for a fresh scan (best-effort, ignored on failure), then `tuya.m.device.get` to read the cached DP 102 from Tuya cloud.
- **Stale data**: if a poll returns no records, the previous readings are retained so entities don't flip to `unknown`.

## Protocol notes

- **Tuya protocol**: v3.4 over TCP 6668 with AES-128 session key (LAN), or HTTPS+AES-128-GCM postData + HMAC-SHA256 sign (cloud).
- **DP 102** decode (51-byte records, per slot):
  - byte 0: validity flag (0x00/0xff = empty)
  - bytes 9–10: temperature little-endian int16, ÷10 → °C (0x7FFF = no probe)
  - bytes 11–12: humidity little-endian uint16, ÷10 → % (0 or 0xFFFF = no humidity)
  - bytes 36–50: sensor name (null-terminated ASCII)
- **DP 129**: write `True` to trigger a BLE sub-sensor scan.
- `nowait=True` is used for the LAN scan trigger so the receive loop can read DP 102 from the socket buffer.

For the gory details of how the cloud login + crypto were reverse-engineered from the INKBIRD app, see `/home/bad/docker/all/build/inkbird/findings.md`.

## Security & privacy

### What this integration sends where

For email/password accounts:
- INKBIRD backend (`api-inkbird.com`): your email + password + country code, over HTTPS with the app's static API-key headers extracted from the APK (not secrets; they identify the app, not the user).
- Tuya cloud (`a1.<region>.tuyaus.com`): every signed API call uses your session token + the rebuilt `getEncryptoKey` AES-128-GCM, identical to what the INKBIRD app does.

For Google accounts:
- INKBIRD backend gets `{username:email, password:"", thirdUid:<sub>, originalThirdUid:<sub>, registerType:2}`. **Your idToken is never transmitted by this integration.** The config flow decodes it locally with `_extract_google_sub()` and only the resulting `sub` (the 21-digit numeric Google account ID) is sent.
- Tuya cloud gets `"1_<sub>"` as the username on the bridging UID-login call.

What's stored in your HA config entry (`.storage/core.config_entries`): `device_id`, `local_key`, `host`, `email`, either `password` or `google_sub`, `region`, `country_code`. Everything is local to your HA instance.

### Known vulnerability in INKBIRD's backend

`POST https://api-inkbird.com/api/smartAgent/user/login` with `registerType=2` and a `thirdUid` accepts the login **without ever verifying the idToken**. The backend never calls Google's tokeninfo endpoint, never checks the JWT signature, never compares `aud` against the production OAuth client. **Anyone who knows a user's numeric Google `sub` can log into that user's INKBIRD account, and through the bridge into their Tuya cloud session.**

This is an authentication-bypass bug in INKBIRD's backend, not in this integration. It exists whether you use this integration or not — any client that POSTs a victim's `sub` to `/smartAgent/user/login` gets a session. The Tuya cloud trusts the INKBIRD-issued bridge unconditionally, so Tuya-side device control follows.

Treat your Google `sub` as a credential equivalent to a password until INKBIRD fixes the backend. Specifically:
- **Don't paste it into JWT debuggers that POST to a server** (use jwt.io which is client-side, or our extractor).
- **Don't share screenshots of the HA config flow form** showing the value.
- **If your `sub` leaks, you cannot rotate it** — Google sub values are permanent per account. Your only remediation is removing the Google sign-in method from your INKBIRD account, which the INKBIRD app may or may not let you do.

### Why this integration uses `sub` directly anyway

Because INKBIRD's backend doesn't validate the idToken, sending the full JWT buys no additional security — the backend ignores everything except `thirdUid`. We chose to extract `sub` locally so it's the only piece of Google identity that travels over the wire, rather than transmitting the full idToken (which expires in ~1 hour anyway) on every login.

The reverse-engineered crypto in `tuya_cloud.py` (HMAC-SHA256 sign, AES-128-GCM postData, RSA-encrypted OEM password) is exactly what the production INKBIRD Android app sends. We do not weaken Tuya's transport security — every cloud call is encrypted and signed the same way the official app does it.

## Debug logging

```yaml
logger:
  logs:
    custom_components.inkbird_wifi: debug
```

The coordinator emits one INFO line per refresh indicating which path was used (`Sensor data now coming via lan` / `via cloud`). DEBUG logs include the full Tuya request bodies and decrypted responses.
