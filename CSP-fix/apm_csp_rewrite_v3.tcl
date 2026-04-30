# ------------------------------------------------------------------------------
# apm_csp_rewrite.tcl  (v2)
#
# Make F5 APM-generated pages (logon, logout, message box, webtop, error,
# EULA, change-password, etc.) strict-CSP compatible without touching the
# APM customization files.
#
# For every text/html response the iRule:
#
#   1. Adds  nonce="<per-response-random>"  to every <script> and <style>.
#   2. Lifts every inline  on<event>="..."  attribute off its element, marks
#      the element with  data-csp-h , and rebinds via addEventListener()
#      inside a nonced <script>.  return-false -> preventDefault().
#   3. Lifts every inline  style="..."  attribute off its element, adds
#      !important to each declaration, and moves it into a class-scoped rule
#      inside a nonced <style> block.
#   4. Rewrites  javascript:  URLs in href / src / action / formaction so the
#      attribute becomes inert ("#" or "about:blank") and the code is rebound
#      as a click/submit listener in the same nonced <script>.
#   5. Strips any pre-existing <meta http-equiv="Content-Security-Policy">
#      (and the Report-Only variant) so it can't intersect our header policy
#      into uselessness.
#   6. Emits / overwrites Content-Security-Policy (or -Report-Only) with a
#      policy that honors the nonce.
#   7. Emits a configurable set of adjacent hardening headers (HSTS, nosniff,
#      Referrer-Policy, Permissions-Policy, COOP/CORP, X-Frame-Options,
#      Cache-Control).
#
# Attach to the virtual server that fronts the APM policy.
# Rollout: set  static::csp_report_only 1  + a report endpoint, watch
# /var/log/ltm (csp_debug 1) and the report collector, then flip to enforce.
# ------------------------------------------------------------------------------

when RULE_INIT {
    # ---- CSP engine --------------------------------------------------------
    # 1 = emit/overwrite the CSP header. 0 = leave headers alone (rewrites
    # still happen). Rewrites are a prerequisite for any strict CSP.
    set static::csp_emit_header 1

    # 1 = send as Content-Security-Policy-Report-Only. Use during rollout to
    # collect violations without breaking users.
    set static::csp_report_only 0

    # 1 = add 'unsafe-eval' to script-src. Needed temporarily if APM code
    # still uses eval / new Function / setTimeout("code",...). Leave 0 and
    # patch offenders when you find them.
    set static::csp_allow_eval 0

    # Optional CSP reporting endpoint. Empty = no report-uri.
    # Example: "/csp-report"  (serve from a dedicated VS that logs the body)
    set static::csp_report_uri ""

    # Base directives. script-src / style-src get the nonce appended at
    # response time. Widen to match third-party assets your APM pages load
    # (corporate fonts, SSO widgets, analytics, etc.).
    set static::csp_base "default-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; frame-src 'self'; form-action 'self'; worker-src 'self'; manifest-src 'self'"

    # ---- Adjacent hardening headers ---------------------------------------
    # Empty string = don't set / leave whatever APM sent.  Non-empty = this
    # iRule removes the existing value and inserts the one below.
    set static::hdr_hsts               "max-age=31536000; includeSubDomains"
    set static::hdr_nosniff            "nosniff"
    set static::hdr_referrer_policy    "strict-origin-when-cross-origin"
    set static::hdr_permissions_policy "geolocation=(), camera=(), microphone=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()"
    set static::hdr_xfo                "DENY"
    set static::hdr_coop               "same-origin"
    set static::hdr_corp               "same-origin"
    # Cache-Control on logon/session pages. Empty = leave APM's value.
    set static::hdr_cache_control      "no-store"

    # ---- Plumbing ---------------------------------------------------------
    set static::csp_max_collect 2097152
    set static::csp_debug 0
}

when HTTP_REQUEST {
    # Rewriter works on plaintext HTML. Strip Accept-Encoding so APM returns
    # uncompressed. Re-compress via an HTTP compression profile if you want
    # gzip to the client.
    HTTP::header remove "Accept-Encoding"
    set csp_want_rewrite 1
}

when HTTP_RESPONSE {
    if {![info exists csp_want_rewrite] || !$csp_want_rewrite} { return }

    set ctype [string tolower [HTTP::header value "Content-Type"]]
    if {![string match "text/html*" $ctype]} { return }

    # ---- Build the CSP value ----------------------------------------------
    set csp_nonce [string map {+ - / _ = ""} \
        [b64encode [md5 "[clock clicks][TMM::cmp_unit][expr {rand()}]"]]]

    set script_src "'self' 'nonce-${csp_nonce}'"
    if {$static::csp_allow_eval} { append script_src " 'unsafe-eval'" }
    set style_src  "'self' 'nonce-${csp_nonce}'"

    set csp_value "${static::csp_base}; script-src $script_src; style-src $style_src"
    if {$static::csp_report_uri ne ""} {
        append csp_value "; report-uri $static::csp_report_uri"
    }

    if {$static::csp_emit_header} {
        HTTP::header remove "Content-Security-Policy"
        HTTP::header remove "Content-Security-Policy-Report-Only"
        if {$static::csp_report_only} {
            HTTP::header insert "Content-Security-Policy-Report-Only" $csp_value
        } else {
            HTTP::header insert "Content-Security-Policy" $csp_value
        }
    }

    # ---- Adjacent hardening headers ---------------------------------------
    foreach {name val} [list \
        "Strict-Transport-Security"    $static::hdr_hsts \
        "X-Content-Type-Options"       $static::hdr_nosniff \
        "Referrer-Policy"              $static::hdr_referrer_policy \
        "Permissions-Policy"           $static::hdr_permissions_policy \
        "X-Frame-Options"              $static::hdr_xfo \
        "Cross-Origin-Opener-Policy"   $static::hdr_coop \
        "Cross-Origin-Resource-Policy" $static::hdr_corp \
        "Cache-Control"                $static::hdr_cache_control \
    ] {
        if {$val ne ""} {
            HTTP::header remove $name
            HTTP::header insert $name $val
        }
    }

    # ---- Collect body for rewrite -----------------------------------------
    set clen [HTTP::header value "Content-Length"]
    if {$clen eq "" || $clen <= 0 || $clen > $static::csp_max_collect} {
        HTTP::collect $static::csp_max_collect
    } else {
        HTTP::collect $clen
    }
}

when HTTP_RESPONSE_DATA {
    set html  [HTTP::payload]
    set nonce $csp_nonce

    # ---- Strip any pre-existing <meta http-equiv="Content-Security..."> ---
    # A CSP meta intersects with the header policy (more restrictive wins per
    # directive), which can silently neutralize our nonce. Remove it.
    regsub -all -nocase \
        {<meta[^>]+http-equiv\s*=\s*["']?Content-Security-Policy(-Report-Only)?["']?[^>]*>} \
        $html "" html

    set out        ""
    set last       0
    set handler_id 0
    set style_id   0
    set jsurl_id   0
    set handler_js ""
    set style_css  ""
    set jsurl_js   ""

    while {1} {
        if {![regexp -indices -start $last \
                {<([A-Za-z][A-Za-z0-9]*)([^>]*)>} $html \
                tagR nameR attrR]} {
            append out [string range $html $last end]
            break
        }
        set t_s [lindex $tagR 0]; set t_e [lindex $tagR 1]
        set n_s [lindex $nameR 0]; set n_e [lindex $nameR 1]
        set a_s [lindex $attrR 0]; set a_e [lindex $attrR 1]

        append out [string range $html $last [expr {$t_s - 1}]]

        set tagName [string tolower [string range $html $n_s $n_e]]
        set attrs   [string range $html $a_s $a_e]

        # --- <script>/<style>: nonce + skip body -------------------------------
        if {$tagName eq "script" || $tagName eq "style"} {
            if {![regexp -nocase {\snonce\s*=} $attrs]} {
                set attrs " nonce=\"$nonce\"$attrs"
            }
            append out "<$tagName$attrs>"
            set closeTag "</$tagName>"
            set closeIdx [string first $closeTag $html [expr {$t_e + 1}]]
            if {$closeIdx < 0} {
                append out [string range $html [expr {$t_e + 1}] end]
                set last [string length $html]
                break
            }
            append out [string range $html [expr {$t_e + 1}] [expr {$closeIdx - 1}]]
            set last $closeIdx
            continue
        }

        # --- Strip inline style="..." ------------------------------------------
        if {[regexp -nocase -indices \
                {\sstyle\s*=\s*(\"([^\"]*)\"|'([^']*)')} \
                $attrs mR _ dqV _ sqV]} {
            set m_s [lindex $mR 0]; set m_e [lindex $mR 1]
            set dq_s [lindex $dqV 0]; set dq_e [lindex $dqV 1]
            set sq_s [lindex $sqV 0]; set sq_e [lindex $sqV 1]
            if {$dq_s >= 0} {
                set css [string range $attrs $dq_s $dq_e]
            } else {
                set css [string range $attrs $sq_s $sq_e]
            }
            set attrs "[string range $attrs 0 [expr {$m_s - 1}]][string range $attrs [expr {$m_e + 1}] end]"

            set fixed ""
            foreach decl [split $css ";"] {
                set decl [string trim $decl]
                if {$decl eq ""} { continue }
                if {![regexp -nocase {!important\s*$} $decl]} {
                    set decl "$decl !important"
                }
                append fixed "$decl; "
            }

            set cls "csp-s-$style_id"
            incr style_id
            append style_css ".$cls { $fixed}\n"

            if {[regexp -nocase -indices \
                    {\sclass\s*=\s*(\"([^\"]*)\"|'([^']*)')} \
                    $attrs cR _ _ cdqV _ csqV]} {
                set cd_s [lindex $cdqV 0]; set cd_e [lindex $cdqV 1]
                set cs_s [lindex $csqV 0]; set cs_e [lindex $csqV 1]
                if {$cd_s >= 0} { set v_s $cd_s; set v_e $cd_e } \
                else            { set v_s $cs_s; set v_e $cs_e }
                set existing [string range $attrs $v_s $v_e]
                set attrs "[string range $attrs 0 [expr {$v_s - 1}]]$existing $cls[string range $attrs [expr {$v_e + 1}] end]"
            } else {
                append attrs " class=\"$cls\""
            }
        }

        # --- Strip inline on<event>="..." --------------------------------------
        set events [list]
        while {[regexp -nocase -indices \
                {\s(on[a-z]+)\s*=\s*(\"([^\"]*)\"|'([^']*)')} \
                $attrs mR evR _ dqV _ sqV]} {
            set m_s [lindex $mR 0]; set m_e [lindex $mR 1]
            set e_s [lindex $evR 0]; set e_e [lindex $evR 1]
            set dq_s [lindex $dqV 0]; set dq_e [lindex $dqV 1]
            set sq_s [lindex $sqV 0]; set sq_e [lindex $sqV 1]
            set evName [string tolower [string range $attrs $e_s $e_e]]
            if {$dq_s >= 0} {
                set code [string range $attrs $dq_s $dq_e]
            } else {
                set code [string range $attrs $sq_s $sq_e]
            }
            lappend events $evName $code
            set attrs "[string range $attrs 0 [expr {$m_s - 1}]][string range $attrs [expr {$m_e + 1}] end]"
        }

        if {[llength $events] > 0} {
            set hid "csp-h-$handler_id"
            incr handler_id
            append attrs " data-csp-h=\"$hid\""

            foreach {ev code} $events {
                regsub -nocase {^\s*javascript\s*:\s*} $code "" code
                set code [string map {&quot; \" &apos; ' &#39; ' &amp; &} $code]
                set safe [string map {"</" "<\\/"} $code]
                set evShort [string range $ev 2 end]
                append handler_js "(function(el)\{if(!el)return;el.addEventListener('$evShort',function(event)\{var _r=(function(event)\{ $safe\n\}).call(el,event);if(_r===false)\{event.preventDefault();event.stopPropagation();\}return _r;\});\})(document.querySelector('\[data-csp-h=\"$hid\"]'));\n"
            }
        }

        # --- Rewrite  javascript:  URLs in href/src/action/formaction ----------
        # CSP blocks javascript: URIs under script-src regardless of nonce, so
        # these have to be neutralized and rebound.
        set jsUrls [list]
        while {[regexp -nocase -indices \
                {\s(href|src|action|formaction)\s*=\s*(\"\s*javascript\s*:([^\"]*)\"|'\s*javascript\s*:([^']*)')} \
                $attrs mR aR _ dqV sqV]} {
            set m_s [lindex $mR 0]; set m_e [lindex $mR 1]
            set an_s [lindex $aR 0]; set an_e [lindex $aR 1]
            set dq_s [lindex $dqV 0]; set dq_e [lindex $dqV 1]
            set sq_s [lindex $sqV 0]; set sq_e [lindex $sqV 1]
            set aName [string tolower [string range $attrs $an_s $an_e]]
            if {$dq_s >= 0} {
                set code [string range $attrs $dq_s $dq_e]
            } else {
                set code [string range $attrs $sq_s $sq_e]
            }
            # Pick a sane inert replacement for the attribute.
            set inert "#"
            if {$aName eq "src" && $tagName eq "iframe"} { set inert "about:blank" }

            lappend jsUrls $aName $code
            set attrs "[string range $attrs 0 [expr {$m_s - 1}]] $aName=\"$inert\"[string range $attrs [expr {$m_e + 1}] end]"
        }

        if {[llength $jsUrls] > 0} {
            set jid "csp-j-$jsurl_id"
            incr jsurl_id
            # Element may already carry data-csp-h; adding data-csp-j alongside
            # is fine -- two markers, two bindings, no conflict.
            append attrs " data-csp-j=\"$jid\""

            foreach {aName code} $jsUrls {
                set code [string map {&quot; \" &apos; ' &#39; ' &amp; &} $code]
                set safe [string map {"</" "<\\/"} $code]
                # action / formaction were form-submission; rebind on submit.
                # href / src / everything else: click.
                if {$aName eq "action" || $aName eq "formaction"} {
                    set evShort "submit"
                } else {
                    set evShort "click"
                }
                append jsurl_js "(function(el)\{if(!el)return;el.addEventListener('$evShort',function(event)\{event.preventDefault();var _r=(function(event)\{ $safe\n\}).call(el,event);if(_r===false)\{event.stopPropagation();\}return _r;\});\})(document.querySelector('\[data-csp-j=\"$jid\"]'));\n"
            }
        }

        append out "<[string range $html $n_s $n_e]$attrs>"
        set last [expr {$t_e + 1}]
    }
    set html $out

    # ---- Inject nonced <style> / <script> before </body> ---------------------
    set inject ""
    if {$style_css ne ""} {
        append inject "<style nonce=\"$nonce\">\n$style_css</style>\n"
    }
    if {$handler_js ne "" || $jsurl_js ne ""} {
        append inject "<script nonce=\"$nonce\">\n(function()\{\n$handler_js$jsurl_js\})();\n</script>\n"
    }
    if {$inject ne ""} {
        if {[regexp -nocase -indices {</body>} $html bR]} {
            set b_s [lindex $bR 0]; set b_e [lindex $bR 1]
            set html "[string range $html 0 [expr {$b_s - 1}]]$inject[string range $html $b_s end]"
        } else {
            append html $inject
        }
    }

    if {$static::csp_debug} {
        log local0. "APM-CSP: uri=[HTTP::header value Host][HTTP::header value :path] handlers=$handler_id styles=$style_id jsurls=$jsurl_id nonce=$nonce len=[string length $html] report_only=$static::csp_report_only"
    }

    HTTP::payload replace 0 [HTTP::payload length] $html
    HTTP::release
}
