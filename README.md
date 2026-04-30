# APM-Tools

A collection of utilities and iRules for F5 BIG-IP Access Policy Manager (APM). The current focus is hardening the security posture of APM-rendered pages so they can pass enterprise vulnerability scanners and modern browser security audits without modifying the APM customization files themselves.

## Contents

| Path | Description |
| --- | --- |
| [`CSP-fix/apm_csp_rewrite_v3.tcl`](CSP-fix/apm_csp_rewrite_v3.tcl) | iRule that injects a strict, nonce-based Content Security Policy and a full set of modern security headers on every APM-generated HTML response (logon, logout, message box, webtop, error, EULA, change-password, etc.). |

---

## CSP-fix — Strict CSP & Security Header iRule for F5 APM

### What problem does it solve?

Out of the box, F5 APM renders HTML pages that rely heavily on patterns modern browsers and vulnerability scanners flag as risky:

- Inline `<script>` and `<style>` blocks with no nonce or hash.
- - Inline event-handler attributes (`onclick`, `onload`, `onsubmit`, `onerror`, …).
  - - Inline `style="…"` attributes on elements.
    - - `javascript:` URLs in `href`, `src`, `action`, and `formaction`.
      - - Missing or weak security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Cache-Control on sensitive responses).
        - - Pre-existing `<meta http-equiv="Content-Security-Policy">` tags shipped in the customization that intersect with (and silently weaken) any header-level policy.
         
          - These are exactly the items called out by tools such as Qualys, Tenable/Nessus, Rapid7, Mozilla Observatory, and SecurityHeaders.com, and they are the reason a default APM virtual server typically scores a `D` or `F` even when the rest of the deployment is hardened.
         
          - The **`apm_csp_rewrite_v3.tcl`** iRule fixes this on the wire — the APM customization files on the box are left untouched. Attach the iRule to the virtual server that fronts the APM access policy and every `text/html` response is rewritten in flight to be compatible with a strict, nonce-based CSP.
         
          - ### What it does on every HTML response
         
          - 1. **Generates a fresh per-response nonce** and adds `nonce="…"` to every `<script>` and `<style>` element.
            2. 2. **Lifts every inline `on<event>="…"` attribute** off its element, tags the element with a `data-csp-h` marker, and rebinds the handler via `addEventListener()` inside a nonced `<script>` block. `return false` is translated to `preventDefault()`.
               3. 3. **Lifts every inline `style="…"` attribute**, adds `!important` to each declaration, and moves it into a class-scoped rule inside a nonced `<style>` block so the visual layout is preserved without inline styles.
                  4. 4. **Neutralizes `javascript:` URLs** in `href` / `src` / `action` / `formaction`. The attribute is rewritten to an inert value (`#` or `about:blank`) and the original code is rebound as a `click` or `submit` listener in the same nonced `<script>` block.
                     5. 5. **Strips any pre-existing `<meta http-equiv="Content-Security-Policy">`** (and the `Report-Only` variant) from the body, so it cannot intersect with the header-level policy and silently disable the nonce.
                        6. 6. **Emits a strict CSP header** (or `Content-Security-Policy-Report-Only` during rollout) tied to the per-response nonce, plus a curated set of modern security headers:
                           7.    - `Strict-Transport-Security`
                                 -    - `X-Frame-Options` / CSP `frame-ancestors`
                                      -    - `X-Content-Type-Options: nosniff`
                                           -    - `Referrer-Policy`
                                                -    - `Permissions-Policy`
                                                     -    - `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`
                                                          -    - `Cache-Control` hardening for HTML responses
                                                               - 7. **Optional CSP reporting** to a configured endpoint so violations can be observed before the policy is enforced.
                                                                
                                                                 8. The net result is that an APM virtual server can pass a strict CSP audit with `script-src 'self' 'nonce-…'` and `style-src 'self' 'nonce-…'` — no `'unsafe-inline'`, no `'unsafe-eval'` — while the stock APM logon, webtop, message-box and error pages continue to function normally.
                                                                
                                                                 9. ### How it works under the hood
                                                                
                                                                 10. The iRule operates entirely in `HTTP_REQUEST`, `HTTP_RESPONSE`, and `HTTP_RESPONSE_DATA`:
                                                                
                                                                 11. - `RULE_INIT` defines tunables (enforce vs. report-only, allow-eval toggle, report URI, max body collect size, header values, debug logging).
                                                                     - - `HTTP_REQUEST` clears any client-supplied CSP-related state and sets a per-connection nonce variable.
                                                                       - - `HTTP_RESPONSE` filters to `text/html` responses, removes weak/duplicate security headers, inserts the hardened header set, and calls `HTTP::collect` so the body can be rewritten.
                                                                         - - `HTTP_RESPONSE_DATA` performs the body rewrites (nonce injection, inline-handler lifting, inline-style lifting, `javascript:` URL neutralization, meta-CSP stripping) and releases the payload.
                                                                          
                                                                           - All regular expressions are anchored to HTML attribute boundaries to minimize false positives, and the rewrite is bounded by a configurable maximum collect size so very large responses are not buffered indefinitely.
                                                                          
                                                                           - ### Configuration tunables (in `RULE_INIT`)
                                                                          
                                                                           - | Variable | Purpose |
                                                                           - | --- | --- |
                                                                           - | `static::csp_emit_header` | `1` to emit/overwrite the CSP header, `0` to leave headers alone (body rewrites still run). |
                                                                           - | `static::csp_report_only` | `1` to send `Content-Security-Policy-Report-Only` during rollout. |
                                                                           - | `static::csp_allow_eval` | `1` to temporarily allow `'unsafe-eval'` in `script-src` while you patch any remaining offenders. |
                                                                           - | `static::csp_report_uri` | Optional report endpoint. Empty disables reporting. |
                                                                           - | `static::csp_max_collect` | Maximum response body size to buffer for rewriting. |
                                                                           - | `static::csp_debug` | `1` to log rewrite activity to `/var/log/ltm`. |
                                                                           - | `static::hdr_*` | Values for HSTS, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Cache-Control, etc. |
                                                                          
                                                                           - ### Deployment
                                                                          
                                                                           - 1. Create a new iRule on the BIG-IP and paste the contents of [`CSP-fix/apm_csp_rewrite_v3.tcl`](CSP-fix/apm_csp_rewrite_v3.tcl).
                                                                             2. 2. Attach the iRule to the HTTPS virtual server that fronts your APM access policy.
                                                                                3. 3. Recommended rollout:
                                                                                   4.    - Set `static::csp_report_only 1` and (optionally) configure `static::csp_report_uri`.
                                                                                         -    - Enable `static::csp_debug 1` and watch `/var/log/ltm` plus the report collector.
                                                                                              -    - Exercise the full APM flow (logon, logout, webtop, message box, EULA, change-password, error pages).
                                                                                                   -    - When violations are clean, set `static::csp_report_only 0` to enforce.
                                                                                                        - 4. Re-run your vulnerability scanner / SecurityHeaders.com / Mozilla Observatory test against the virtual server to confirm the new score.
                                                                                                         
                                                                                                          5. ### Compatibility
                                                                                                         
                                                                                                          6. - Targeted at F5 BIG-IP APM virtual servers serving APM-rendered HTML.
                                                                                                             - - Operates only on `text/html` responses; binary, JSON, and other content types are passed through unchanged.
                                                                                                               - - The APM customization files on the box are not modified, so APM upgrades and hotfixes do not regress the fix.
                                                                                                                
                                                                                                                 - ### Disclaimer
                                                                                                                
                                                                                                                 - Provided as-is under the repository license. Test in a non-production environment first; CSP is intentionally strict, and any third-party content injected into APM pages (custom logos, analytics, federated widgets) may need to be added to the policy before enforcing.
                                                                                                                 - 
