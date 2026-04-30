# APM-Tools

A collection of utilities and iRules for F5 BIG-IP Access Policy Manager (APM). The current focus is hardening the security posture of APM-rendered pages so they pass enterprise vulnerability scanners and modern browser security audits without modifying the APM customization files on the box.

## Contents

- [`CSP-fix/apm_csp_rewrite_v3.tcl`](CSP-fix/apm_csp_rewrite_v3.tcl) — iRule that injects a strict, nonce-based Content Security Policy and a full set of modern security headers on every APM-generated HTML response (logon, logout, message box, webtop, error, EULA, change-password, etc.).

---

## CSP-fix — Strict CSP & Security Header iRule for F5 APM

### What it addresses

Out of the box, APM renders HTML pages that rely on patterns modern browsers and vulnerability scanners flag as risky. Default APM virtual servers commonly score a `D` or `F` on tools like Qualys, Tenable/Nessus, Rapid7, Mozilla Observatory, and SecurityHeaders.com because of the following issues:

- Inline `<script>` and `<style>` blocks with no nonce or hash.
- Inline event-handler attributes (`onclick`, `onload`, `onsubmit`, `onerror`, etc.).
- Inline `style="..."` attributes on elements.
- `javascript:` URLs in `href`, `src`, `action`, and `formaction`.
- Missing or weak security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Cache-Control).
- Pre-existing `<meta http-equiv="Content-Security-Policy">` tags shipped in the customization that intersect with and silently weaken any header-level policy.

The `apm_csp_rewrite_v3.tcl` iRule fixes these on the wire. The APM customization files on the box are left untouched. Attach the iRule to the virtual server that fronts the APM access policy and every `text/html` response is rewritten in flight to be compatible with a strict, nonce-based CSP.

### What it does on every HTML response

**1. Per-response nonce.** Generates a fresh nonce and adds `nonce="..."` to every `<script>` and `<style>` element.

**2. Inline event handlers.** Lifts every inline `on<event>="..."` attribute off its element, tags the element with a `data-csp-h` marker, and rebinds the handler via `addEventListener()` inside a nonced `<script>` block. `return false` is translated to `preventDefault()`.

**3. Inline styles.** Lifts every inline `style="..."` attribute, adds `!important` to each declaration, and moves it into a class-scoped rule inside a nonced `<style>` block so the visual layout is preserved without inline styles.

**4. `javascript:` URLs.** Rewrites `javascript:` URLs in `href`, `src`, `action`, and `formaction` to an inert value (`#` or `about:blank`). The original code is rebound as a `click` or `submit` listener in the same nonced `<script>` block.

**5. Legacy meta CSP.** Strips any pre-existing `<meta http-equiv="Content-Security-Policy">` tags (and the `Report-Only` variant) from the body so they cannot intersect with the header-level policy and silently disable the nonce.

**6. Strict CSP header.** Emits a strict `Content-Security-Policy` header (or `Content-Security-Policy-Report-Only` during rollout) tied to the per-response nonce, plus a curated set of modern security headers: `Strict-Transport-Security`, `X-Frame-Options` and CSP `frame-ancestors`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, and hardened `Cache-Control` for HTML responses.

**7. Optional reporting.** Sends CSP violation reports to a configured endpoint so issues can be observed before the policy is enforced.

The net result is an APM virtual server that passes a strict CSP audit with `script-src 'self' 'nonce-...'` and `style-src 'self' 'nonce-...'` — no `'unsafe-inline'`, no `'unsafe-eval'` — while the stock APM logon, webtop, message-box, and error pages continue to function normally.

### How it works

The iRule operates entirely in `HTTP_REQUEST`, `HTTP_RESPONSE`, and `HTTP_RESPONSE_DATA`.

`RULE_INIT` defines tunables (enforce vs. report-only, allow-eval toggle, report URI, max body collect size, header values, debug logging). `HTTP_REQUEST` clears any client-supplied CSP-related state and sets a per-connection nonce variable. `HTTP_RESPONSE` filters to `text/html` responses, removes weak or duplicate security headers, inserts the hardened header set, and calls `HTTP::collect` so the body can be rewritten. `HTTP_RESPONSE_DATA` performs the body rewrites (nonce injection, inline-handler lifting, inline-style lifting, `javascript:` URL neutralization, and meta-CSP stripping) and releases the payload.

All regular expressions are anchored to HTML attribute boundaries to minimize false positives, and the rewrite is bounded by a configurable maximum collect size so very large responses are not buffered indefinitely.

### Configuration tunables

Set in `RULE_INIT`:

- `static::csp_emit_header` — `1` to emit/overwrite the CSP header, `0` to leave headers alone (body rewrites still run).
- `static::csp_report_only` — `1` to send `Content-Security-Policy-Report-Only` during rollout.
- `static::csp_allow_eval` — `1` to temporarily allow `'unsafe-eval'` in `script-src` while you patch any remaining offenders.
- `static::csp_report_uri` — optional report endpoint; empty disables reporting.
- `static::csp_max_collect` — maximum response body size to buffer for rewriting.
- `static::csp_debug` — `1` to log rewrite activity to `/var/log/ltm`.
- `static::hdr_*` — values for HSTS, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Cache-Control, etc.

### Deployment

1. Create a new iRule on the BIG-IP and paste the contents of [`CSP-fix/apm_csp_rewrite_v3.tcl`](CSP-fix/apm_csp_rewrite_v3.tcl).
2. Attach the iRule to the HTTPS virtual server that fronts your APM access policy.
3. Roll out in report-only mode first: set `static::csp_report_only 1`, optionally configure `static::csp_report_uri`, and enable `static::csp_debug 1`.
4. Exercise the full APM flow (logon, logout, webtop, message box, EULA, change-password, error pages) and watch `/var/log/ltm` plus the report collector.
5. When violations are clean, set `static::csp_report_only 0` to enforce.
6. Re-run your vulnerability scanner / SecurityHeaders.com / Mozilla Observatory test against the virtual server to confirm the new score.

### Compatibility

Targeted at F5 BIG-IP APM virtual servers serving APM-rendered HTML. The iRule operates only on `text/html` responses; binary, JSON, and other content types are passed through unchanged. The APM customization files on the box are not modified, so APM upgrades and hotfixes do not regress the fix.

### Disclaimer

Provided as-is under the repository license. Test in a non-production environment first. CSP is intentionally strict, and any third-party content injected into APM pages (custom logos, analytics, federated widgets) may need to be added to the policy before enforcing.
