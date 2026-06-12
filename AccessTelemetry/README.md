# AccessTelemetry — Client Telemetry & Anomaly-Detection iRules for F5 BIG-IP

A two-layer telemetry framework for detecting user/client anomalies on BIG-IP virtual
servers fronting APM and/or AWAF-protected applications. Layer 1 (this folder) collects
and distributes the telemetry; Layer 2 (a local visualization dashboard built with
iApps LX) will be added once the telemetry layer is proven — the local table buffer it
will read from is already implemented here.

## Files

| File | Role |
|---|---|
| [`atel_telemetry_main.tcl`](atel_telemetry_main.tcl) | **Execution iRule.** All traffic events, all toggles at the top in `RULE_INIT`. |
| [`atel_telemetry_lib.tcl`](atel_telemetry_lib.tcl) | **Proc library.** Every collector/emitter as a `proc`, reusable from other iRules via `call atel_telemetry_lib::<proc>`. |

Install both as iRules on the BIG-IP (names must be `atel_telemetry_lib` and whatever
you like for main), then attach **both** to the virtual server. Only the main iRule
defines traffic events; the library contributes procs.

## Telemetry items

Each item is independently switchable with three states — `0` off, `1` standard,
`2` debug — via `static::atel_en(<item>)`:

| Item | Source | Standard captures | Debug adds |
|---|---|---|---|
| `client_ip` | TCP source / XFF | effective IP + source (`tcp`/`xff`) | raw TCP `ip:port` |
| `ip_rep` | `IP::reputation` (IP Intelligence subscription) | category list | per-lookup log line |
| `geo` | `whereis` | country, continent, state | city, zip, ISP, org |
| `ja4` | TLS ClientHello parse (or external f5-ja4 iRule) | JA4 fingerprint | `ja4_r` raw fingerprint + log |
| `ja4t` | TCP SYN options via `DATAGRAM::tcp` in `FLOW_INIT` | JA4T fingerprint | — |
| `ja4l` | `clock clicks` deltas across TCP + TLS handshakes | JA4L `tcpLatency_ttl_tlsLatency` (client & server light distance) | log line |
| `ja4h` | HTTP request headers/cookies per the FoxIO JA4H spec | JA4H fingerprint | `ja4h_r` raw (header + cookie-name lists) + log |
| `identity` | APM session → `Authorization` header (Basic user / Bearer JWT claim) → cookie | identity + source | raw cookie value (standard mode stores a sha256-12 pseudonym) |
| `device_awaf` | `ASM::fingerprint` (AWAF DeviceID) | device ID on inspected requests | — |
| `device_bot` | `BOTDEFENSE::device_id` | device ID | action + reason log |
| `device_xc` | Header forwarded by F5 Distributed Cloud Bot Defense | header value | — |

All collectors are `catch`-wrapped: a missing license (IPI), missing geolocation DB,
or unprovisioned feature degrades to "field absent", never a TCL error.

## Distribution layer (all independently toggleable)

- **HSL remote logging** (`atel_emit_hsl`) — records sent to an LTM pool of log
  collectors over UDP/TCP, formatted as JSON or `key="value"` pairs
  (`atel_record_format`).
- **APM session variables** (`atel_apm_sessionvars`) — telemetry mirrored to
  `session.custom.atel.*` for use inside the access policy (branch rules, custom
  logging, irule-event agents).
- **WAF violation decoration** (`atel_waf_decorate`) — on `ASM_REQUEST_DONE`, emits a
  record carrying `support_id`, `asm_status`, violation names, and severity alongside
  the full client telemetry, so a SIEM or the dashboard can join WAF violations to
  JA4/geo/reputation/identity by support ID. `atel_waf_decorate_all 1` decorates every
  inspected request, not just blocked/alerted ones.
- **Downstream HTTP headers** (`atel_emit_headers`) — chosen items (`atel_hdr_items`)
  inserted toward the pool as `X-ATel-<item>`. Inbound headers with the `X-ATel-`
  prefix are always stripped first (anti-spoofing).
- **Local table buffer** (`atel_emit_table`) — records stored in the session table
  (subtable `atel_events`, ring-buffered to `atel_table_max` entries, TTL
  `atel_table_ttl`). This is the read surface for the future iApps LX dashboard: it
  pages through `atel_events` using the sequence counter kept in `atel_events_meta/seq`.
- **Local LTM log** (`atel_log_local`) — every record also to `/var/log/ltm`.

Emission granularity: one record per TCP flow by default (first HTTP request), or every
request with `atel_emit_per_request 1`.

## APM behavior (works with APM enabled or disabled)

Two independent capture points, because not every session completes logon:

- `atel_apm_presession 1` — at `ACCESS_SESSION_STARTED`: telemetry pushed into session
  variables and a record emitted (`event=apm_session_started`) **before** the access
  policy runs. Captures abandoned/failed logons.
- `atel_apm_completed 1` — at `ACCESS_POLICY_COMPLETED`: re-pushes variables, picks up
  the authoritative `session.logon.last.username`, and emits
  `event=apm_policy_completed` with the policy result.

Session IDs are truncated to 8 characters in standard mode (full SID only in debug).
With no APM profile attached the ACCESS events simply never fire and the HTTP-level
pipeline works standalone.

> **Provisioning note:** iRules referencing `ACCESS_*`, `ASM_*`, or `BOTDEFENSE_*`
> events only load if the corresponding module is **provisioned** on the box (it does
> not need to be attached to the virtual). If a module is not provisioned, comment out
> that event section at the bottom of `atel_telemetry_main.tcl` — everything else is
> unaffected.

## Coexistence with existing iRules

- **Priority:** every event is declared `priority 900`, so this rule runs *after* any
  iRule using the default priority 500 (in iRules a lower number runs first). To
  reorder, search-and-replace `priority 900` in the main iRule.
- **JA4 modes:** `atel_ja4_mode "compute"` parses the ClientHello itself (briefly using
  `TCP::collect` in `CLIENT_ACCEPTED`/`CLIENT_DATA`). If the
  [f5devcentral/f5-ja4](https://github.com/f5devcentral/f5-ja4) `ja4.irule` is already
  attached to the virtual, set `atel_ja4_mode "external"` instead — the main iRule then
  reads that rule's `$ja4_fingerprint` connection variable and never touches
  `TCP::collect`, so only one rule owns payload collection.
- The `CLIENT_DATA` handler only acts on collections it initiated.
- **Standalone f5-ja4 iRules:** if any of the standalone `JA4H`/`JA4T`/`JA4L` iRules
  from f5devcentral are still attached to the virtual, they keep generating their own
  fingerprints, log lines, and `X-JA4*` headers independently of this framework's
  toggles. Detach them and enable the corresponding `atel_en(...)` item here instead
  (only the `ja4.irule` has a supported coexistence path via `atel_ja4_mode external`).

## Trust XFF

`atel_trust_xff 1` makes the left-most address of `X-Forwarded-For` (header name
configurable via `atel_xff_header`) the *effective* client IP after validation —
GEO and IP-reputation lookups are re-run against it, and `ip_src` records whether the
value came from `xff` or `tcp`. Only enable behind a trusted proxy/CDN tier that
overwrites the header.

## Device IDs: requirements & timing

Device IDs are JavaScript-derived, so they need both configuration and a round trip:

- **`device_awaf`** (`ASM::fingerprint`) — the ASM/AWAF policy must actually fingerprint
  clients: enable *Session Tracking → Use Device ID* in the policy (Security ›
  Application Security › Sessions and Logins). Without it the command returns nothing.
- **`device_bot`** (`BOTDEFENSE::device_id`) — requires a Bot Defense profile attached
  to the virtual with **Device ID mode** set to *Generate Before Access* or *Generate
  After Access*. Without the profile, `BOTDEFENSE_ACTION` never fires at all.
- **`device_xc`** — only populated when F5 Distributed Cloud fronts the virtual and is
  configured to forward its bot/device header (`atel_xc_header`).
- **First-request gap:** the ID is minted by injected JavaScript, so the *first* request
  from a new client never carries one — it appears once the browser has executed the
  challenge and re-sent. Both module events also fire **after** this iRule's
  `HTTP_REQUEST` record is emitted, so in per-flow emission mode a newly seen device ID
  triggers a one-time supplemental record with `event=device_id` carrying the full
  telemetry set; in `atel_emit_per_request 1` mode the IDs simply appear in subsequent
  request records. Downstream `X-ATel-*` headers carry device IDs from the next
  keep-alive request onward.

### Triage checklist (debug mode)

Set the item to debug (`atel_en(device_awaf) 2` / `atel_en(device_bot) 2`), browse a
few pages, and watch `/var/log/ltm` (`tail -f /var/log/ltm | grep ATEL`). Debug lines
are logged at *info* severity so default syslog filtering never hides them. Then:

| Symptom | Cause / fix |
|---|---|
| **No `ATEL(device_awaf)` lines at all** | `ASM_REQUEST_DONE` is not firing. The #1 cause: the security policy property **"Trigger ASM iRule Events" is Disabled by default**. Enable it (Security › Application Security › Policies › *policy* › Policy Properties, Advanced view → Trigger ASM iRule Events: **Enabled / Normal Mode**) and **Apply Policy**. Also confirm the ASM policy is attached to this virtual. This setting gates `device_awaf` *and* all WAF decoration records. |
| `ATEL(device_awaf): ... no fingerprint` lines | Events fire but the policy isn't fingerprinting clients — enable *Session Tracking → Use Device ID* in the policy and Apply. |
| **No `ATEL(device_bot)` lines at all** | `BOTDEFENSE_ACTION` is not firing — no Bot Defense profile is attached to the virtual (Virtual Server › Security › Policies). |
| `ATEL(device_bot): device_id= action=... reason=...` (empty id) | Profile attached but Device ID mode is *None*, or the client hasn't completed the JS challenge yet (first request from a new browser never has an ID). Set Device ID mode to *Generate Before/After Access* in the Bot Defense profile. |

## Quick start

1. Create iRule `atel_telemetry_lib` from `atel_telemetry_lib.tcl`.
2. Create iRule `atel_telemetry_main` from `atel_telemetry_main.tcl`.
3. Edit the toggle block at the top of `atel_telemetry_main` (everything lives in
   `RULE_INIT`; nothing below it needs changes). If using HSL, create the log-collector
   pool first and set `atel_hsl_pool`.
4. Attach both iRules to the virtual server.
5. Validate with `static::atel_debug 1` and `static::atel_log_local 1`, watching
   `/var/log/ltm`, then turn both off for production.

Inspect the local buffer from tmsh while the dashboard layer is pending:

```
tmsh show sys table atel_events
```

## Requirements / notes

- Tested model: TMOS 16.1+ (matches the f5devcentral JA4 iRules' support statement).
- `ip_rep` needs the IP Intelligence subscription; `geo` city/ISP/org fields need the
  extended geolocation data file. Both degrade silently when absent.
- JA4/JA4T/JA4L collectors are adapted from
  [f5devcentral/f5-ja4](https://github.com/f5devcentral/f5-ja4) — JA4 TLS is BSD
  3-Clause; JA4T/JA4L are © 2024 FoxIO, LLC under FoxIO License 1.1
  ([spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)).
- Bearer-token identity decodes the JWT payload for the configured claim
  (`atel_identity_claim`, default `sub`) **without signature validation** — telemetry
  only, never authorization.
- Passwords from `Authorization: Basic` are never stored or logged; only the username.

## Roadmap

- [x] JA4H (HTTP fingerprint) collector.
- [ ] iApps LX visualization dashboard reading the `atel_events` subtable.
- [ ] Optional anomaly scoring proc (JA4↔geo↔identity consistency across a session).
