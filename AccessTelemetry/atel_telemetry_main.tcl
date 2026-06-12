###############################################################################################
#  atel_telemetry_main  --  Access Telemetry execution iRule
#
#  Collects per-connection client telemetry (client IP / XFF, IP reputation, GEO,
#  JA4, JA4T, JA4L, AWAF & Bot-Defense device IDs, XC bot device ID, user identity)
#  and fans it out to: HSL remote logging, APM session variables, WAF violation
#  decoration records, downstream HTTP headers, and a local session-table buffer
#  for an iApps LX visualization dashboard.
#
#  REQUIRES: iRule "atel_telemetry_lib" (the proc library) on the same BIG-IP.
#  Attach BOTH iRules to the virtual server (lib first is not required; only
#  this rule defines traffic events).
#
#  -------------------------------------------------------------------------------------------
#  EXECUTION PRIORITY / COEXISTENCE
#  -------------------------------------------------------------------------------------------
#  Every event below is declared with "priority 900" so this iRule runs AFTER
#  any existing iRules that use the default priority (500).  In iRules a LOWER
#  number runs FIRST, so to move this rule earlier or later in the chain,
#  search-and-replace "priority 900" with the value you want.
#
#  Module events note: the ACCESS_* blocks require APM to be provisioned and the
#  ASM_*/BOTDEFENSE_* blocks require ASM/Bot-Defense to be provisioned on the
#  box (provisioned, not necessarily attached to this virtual).  If a module is
#  not provisioned, comment out its event block at the bottom of this file --
#  everything else keeps working.
###############################################################################################

when RULE_INIT {

    # =========================================================================================
    #  TOGGLES -- edit everything here; nothing below RULE_INIT needs changes
    # =========================================================================================

    # ---- master switches --------------------------------------------------------------------
    set static::atel_enabled        1       ;# 0 = iRule fully passive
    set static::atel_debug          0       ;# 1 = global debug (forces debug for every item)

    # ---- per-telemetry-item switches:  0 = off, 1 = standard, 2 = debug ---------------------
    set static::atel_en(client_ip)   1      ;# effective client IP (+ source tcp|xff)
    set static::atel_en(ip_rep)      1      ;# IP Intelligence categories (IPI license req.)
    set static::atel_en(geo)         1      ;# whereis country/continent/state (+city/isp/org in debug)
    set static::atel_en(ja4)         1      ;# JA4 TLS ClientHello fingerprint
    set static::atel_en(ja4t)        1      ;# JA4T TCP SYN fingerprint
    set static::atel_en(ja4l)        1      ;# JA4L light distance (tcp latency _ ttl _ tls latency)
    set static::atel_en(ja4h)        1      ;# JA4H HTTP request fingerprint
    set static::atel_en(identity)    1      ;# user identity (APM / Authorization / Cookie)
    set static::atel_en(device_awaf) 1      ;# AWAF (ASM) DeviceID via ASM::fingerprint
    set static::atel_en(device_bot)  1      ;# Bot Defense profile DeviceID (BOTDEFENSE::device_id)
    set static::atel_en(device_xc)   0      ;# F5 XC bot DeviceID forwarded as a header (see below)

    # ---- client IP / XFF --------------------------------------------------------------------
    set static::atel_trust_xff      0                   ;# 1 = trust X-Forwarded-For (left-most IP)
    set static::atel_xff_header     "X-Forwarded-For"   ;# header to trust when enabled

    # ---- JA4 collection mode ----------------------------------------------------------------
    #  "compute"  = this iRule parses the ClientHello itself (uses TCP::collect briefly
    #               in CLIENT_ACCEPTED/CLIENT_DATA).
    #  "external" = read the $ja4_fingerprint connection variable set by the
    #               f5devcentral/f5-ja4 ja4.irule already attached to this virtual.
    #               Use this mode when coexisting with that iRule so only one
    #               rule owns TCP::collect.
    set static::atel_ja4_mode       "compute"

    # ---- identity sources (checked in order; first hit wins) ---------------------------------
    set static::atel_identity_sources { apm authorization cookie }
    set static::atel_identity_claim   "sub"             ;# JWT claim for Bearer tokens
    set static::atel_identity_cookie  "MRHSession"      ;# cookie name; value is sha256-hashed
                                                         ;# in standard mode, raw only in debug
    # ---- XC bot DeviceID header ---------------------------------------------------------------
    set static::atel_xc_header      "X-F5-Bot-Device-Id" ;# header inserted by XC Bot Defense

    # ---- emission: HSL remote logging ----------------------------------------------------------
    set static::atel_emit_hsl       0                   ;# 1 = forward records via HSL
    set static::atel_hsl_pool       "pool_telemetry"    ;# LTM pool of syslog/log collectors
    set static::atel_hsl_proto      "UDP"               ;# UDP | TCP
    set static::atel_record_format  "json"              ;# json | kv (applies to HSL/table/local)

    # ---- emission: local session-table buffer (for the iApps LX dashboard) --------------------
    set static::atel_emit_table     1
    set static::atel_table_name    "atel_events"        ;# subtable name
    set static::atel_table_ttl      900                 ;# seconds each record is kept
    set static::atel_table_max      5000                ;# ring-buffer cap (0 = unlimited)

    # ---- emission: local /var/log/ltm ----------------------------------------------------------
    set static::atel_log_local      0                   ;# 1 = also log every record locally

    # ---- emission: per-request or per-flow ------------------------------------------------------
    set static::atel_emit_per_request 0                 ;# 0 = one record per TCP flow (first
                                                         ;#     HTTP request), 1 = every request

    # ---- downstream HTTP headers ---------------------------------------------------------------
    set static::atel_emit_headers   0                   ;# 1 = insert telemetry headers to pool
    set static::atel_hdr_prefix     "X-ATel-"           ;# inbound headers with this prefix are
                                                         ;# always stripped (anti-spoofing)
    set static::atel_hdr_items     { client_ip geo_country ja4 ja4t ja4l identity }

    # ---- APM integration -------------------------------------------------------------------------
    set static::atel_apm_sessionvars 1                  ;# 1 = mirror telemetry into APM session
    set static::atel_apm_var_prefix "session.custom.atel." ;# variables for use in access policy
    set static::atel_apm_presession  1                  ;# 1 = push vars + emit a record at
                                                         ;#     ACCESS_SESSION_STARTED (captures
                                                         ;#     sessions that never finish logon)
    set static::atel_apm_completed   1                  ;# 1 = push vars + emit a record at
                                                         ;#     ACCESS_POLICY_COMPLETED (adds
                                                         ;#     authenticated identity + result)

    # ---- WAF (ASM/AWAF) violation decoration ------------------------------------------------------
    set static::atel_waf_decorate    1                  ;# 1 = emit a telemetry record carrying the
                                                         ;#     ASM support_id so SIEM/dashboards can
                                                         ;#     join violations to client telemetry
    set static::atel_waf_decorate_all 0                 ;# 0 = only when request did NOT pass,
                                                         ;#     1 = decorate every inspected request
    # =========================================================================================
    #  END OF TOGGLES
    # =========================================================================================
}

###############################################################################################
#  L4 collection
###############################################################################################

when FLOW_INIT priority 900 {
    if { !$static::atel_enabled } { return }

    # JA4T must be read off the client SYN -- only visible here
    if { $static::atel_en(ja4t) } {
        set atel(ja4t) [call atel_telemetry_lib::ja4t_collect]
        if { $atel(ja4t) eq "" } { unset atel(ja4t) }
    }

    if { $static::atel_en(ja4l) } {
        set atel_ja4l_ts1 [clock clicks]
    }
}

when CLIENT_ACCEPTED priority 900 {
    if { !$static::atel_enabled } { return }

    set atel(_vs) [virtual name]

    # JA4L: TCP leg = (SYN -> accept) / 2, plus client TTL
    if { $static::atel_en(ja4l) } {
        set atel_ja4l_tcp 0
        if { [info exists atel_ja4l_ts1] } {
            set atel_ja4l_tcp [expr {([clock clicks] - $atel_ja4l_ts1) / 2}]
            if { $atel_ja4l_tcp < 0 } { set atel_ja4l_tcp 0 }
            if { $atel_ja4l_tcp > 10000000 } { set atel_ja4l_tcp 10000000 }
        }
        set atel_ja4l_ttl 0
        catch { set atel_ja4l_ttl [IP::ttl] }
    }

    # JA4 compute mode: buffer the ClientHello before the SSL stack consumes it
    if { $static::atel_en(ja4) && $static::atel_ja4_mode eq "compute" } {
        set atel_ja4_collecting 1
        TCP::collect
    }
}

when CLIENT_DATA priority 900 {
    # Only act on collections we initiated; if another iRule is also collecting,
    # it owns its own release.
    if { ![info exists atel_ja4_collecting] || !$atel_ja4_collecting } { return }

    set res [call atel_telemetry_lib::ja4_parse [TCP::payload] [TCP::payload length]]
    switch [lindex $res 0] {
        "need" {
            TCP::collect [lindex $res 1]
            return
        }
        "done" {
            set atel(ja4) [lindex $res 1]
            if { $static::atel_en(ja4) >= 2 || $static::atel_debug } {
                set atel(ja4_r) [lindex $res 2]
                call atel_telemetry_lib::dbg "ja4" "JA4=$atel(ja4) src=[IP::client_addr]:[TCP::client_port]"
            }
        }
    }
    set atel_ja4_collecting 0
    TCP::release
}

###############################################################################################
#  TLS collection (JA4L application leg)
###############################################################################################

when CLIENTSSL_CLIENTHELLO priority 900 {
    if { !$static::atel_enabled || !$static::atel_en(ja4l) } { return }
    set atel_ja4l_ts3 [clock clicks]
}

when CLIENTSSL_HANDSHAKE priority 900 {
    if { !$static::atel_enabled || !$static::atel_en(ja4l) } { return }

    set app_lat 0
    if { [info exists atel_ja4l_ts3] } {
        set app_lat [expr {([clock clicks] - $atel_ja4l_ts3) / 2}]
        if { $app_lat < 0 } { set app_lat 0 }
        if { $app_lat > 10000000 } { set app_lat 10000000 }
    }
    if { ![info exists atel_ja4l_tcp] } { set atel_ja4l_tcp 0 }
    if { ![info exists atel_ja4l_ttl] } { set atel_ja4l_ttl 0 }

    set atel(ja4l) "${atel_ja4l_tcp}_${atel_ja4l_ttl}_${app_lat}"
    if { $static::atel_en(ja4l) >= 2 || $static::atel_debug } {
        call atel_telemetry_lib::dbg "ja4l" "JA4L=$atel(ja4l) src=[IP::client_addr]"
    }
}

###############################################################################################
#  HTTP collection + emission
###############################################################################################

when HTTP_REQUEST priority 900 {
    if { !$static::atel_enabled } { return }

    # --- anti-spoofing: our telemetry headers never come from the client ---
    foreach h [HTTP::header names] {
        if { [string match -nocase "${static::atel_hdr_prefix}*" $h] } {
            HTTP::header remove $h
        }
    }

    # --- effective client IP (XFF-aware) ---
    set eff_ip [IP::client_addr]
    if { $static::atel_en(client_ip) } {
        set xff ""
        if { $static::atel_trust_xff } {
            set xff [HTTP::header value $static::atel_xff_header]
        }
        set r [call atel_telemetry_lib::effective_ip [IP::client_addr] $xff $static::atel_trust_xff]
        set eff_ip          [lindex $r 0]
        set atel(client_ip) $eff_ip
        set atel(ip_src)    [lindex $r 1]
        if { $static::atel_en(client_ip) >= 2 || $static::atel_debug } {
            set atel(tcp_src) "[IP::client_addr]:[TCP::client_port]"
        }
    }

    # --- GEO + IP reputation on the effective IP (re-run if XFF changes it) ---
    if { ![info exists atel(_geo_ip)] || $atel(_geo_ip) ne $eff_ip } {
        set atel(_geo_ip) $eff_ip
        if { $static::atel_en(geo) } {
            foreach {k v} [call atel_telemetry_lib::geo $eff_ip \
                    [expr {$static::atel_en(geo) >= 2 || $static::atel_debug}]] {
                set atel($k) $v
            }
        }
        if { $static::atel_en(ip_rep) } {
            set rep [call atel_telemetry_lib::iprep $eff_ip]
            if { $rep ne "" } { set atel(ip_rep) $rep }
            if { $static::atel_en(ip_rep) >= 2 || $static::atel_debug } {
                call atel_telemetry_lib::dbg "ip_rep" "ip=$eff_ip rep=\"$rep\""
            }
        }
    }

    # --- JA4 external mode: pick up the f5devcentral ja4.irule result ---
    if { $static::atel_en(ja4) && $static::atel_ja4_mode eq "external"
         && ![info exists atel(ja4)] && [info exists ja4_fingerprint] } {
        set atel(ja4) $ja4_fingerprint
    }

    # --- JA4H HTTP fingerprint ---
    if { $static::atel_en(ja4h)
         && (![info exists atel(ja4h)] || $static::atel_emit_per_request) } {
        set jh [call atel_telemetry_lib::ja4h_collect \
                [expr {$static::atel_en(ja4h) >= 2 || $static::atel_debug}]]
        set atel(ja4h) [lindex $jh 0]
        if { [lindex $jh 1] ne "" } {
            set atel(ja4h_r) [lindex $jh 1]
            call atel_telemetry_lib::dbg "ja4h" "JA4H=$atel(ja4h) raw=$atel(ja4h_r)"
        }
    }

    # --- XC bot DeviceID (header inserted by F5 Distributed Cloud) ---
    if { $static::atel_en(device_xc) } {
        set xcid [HTTP::header value $static::atel_xc_header]
        if { $xcid ne "" } { set atel(device_xc) $xcid }
    }

    # --- user identity ---
    if { $static::atel_en(identity)
         && (![info exists atel(identity)] || $static::atel_emit_per_request) } {
        foreach src $static::atel_identity_sources {
            set id ""
            switch $src {
                "apm" {
                    catch { set id [ACCESS::session data get "session.logon.last.username"] }
                }
                "authorization" {
                    set auth [HTTP::header value "Authorization"]
                    if { $auth ne "" } {
                        set id [call atel_telemetry_lib::identity_basic $auth]
                        if { $id eq "" } {
                            set id [call atel_telemetry_lib::identity_bearer $auth $static::atel_identity_claim]
                        }
                    }
                }
                "cookie" {
                    set cv ""
                    catch { set cv [HTTP::cookie value $static::atel_identity_cookie] }
                    if { $cv ne "" } {
                        if { $static::atel_en(identity) >= 2 || $static::atel_debug } {
                            set id $cv
                        } else {
                            set id "ck_[call atel_telemetry_lib::hash12 $cv]"
                        }
                    }
                }
            }
            if { $id ne "" } {
                set atel(identity)     $id
                set atel(identity_src) $src
                break
            }
        }
    }

    # --- downstream telemetry headers ---
    if { $static::atel_emit_headers } {
        foreach item $static::atel_hdr_items {
            if { [info exists atel($item)] } {
                HTTP::header insert "${static::atel_hdr_prefix}${item}" $atel($item)
            }
        }
    }

    # --- mirror into APM session variables when a session already exists ---
    if { $static::atel_apm_sessionvars } {
        set pairs [list]
        foreach k [lsort [array names atel]] {
            if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
        }
        catch {
            if { [ACCESS::session sid] ne "" } {
                call atel_telemetry_lib::apm_setvars $pairs $static::atel_apm_var_prefix
            }
        }
    }

    # --- emit one record per flow (or per request) ---
    if { $static::atel_emit_per_request || ![info exists atel_emitted] } {
        set atel_emitted 1
        set pairs [list ts [clock seconds] event "http_request"]
        if { [info exists atel(_vs)] } { lappend pairs vs $atel(_vs) }
        if { $static::atel_debug } {
            lappend pairs host [HTTP::host] uri [HTTP::uri] method [HTTP::method]
        }
        foreach k [lsort [array names atel]] {
            if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
        }
        call atel_telemetry_lib::emit $pairs
    }
}

###############################################################################################
#  APM integration
#  (requires APM provisioned; comment this section out otherwise)
###############################################################################################

when ACCESS_SESSION_STARTED priority 900 {
    if { !$static::atel_enabled || !$static::atel_apm_presession } { return }

    set pairs [list ts [clock seconds] event "apm_session_started"]
    if { [info exists atel(_vs)] } { lappend pairs vs $atel(_vs) }
    catch {
        if { $static::atel_debug } {
            lappend pairs sid [ACCESS::session sid]
        } else {
            lappend pairs sid [string range [ACCESS::session sid] 0 7]
        }
    }
    foreach k [lsort [array names atel]] {
        if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
    }

    if { $static::atel_apm_sessionvars } {
        set vpairs [list]
        foreach k [lsort [array names atel]] {
            if { [string index $k 0] ne "_" } { lappend vpairs $k $atel($k) }
        }
        call atel_telemetry_lib::apm_setvars $vpairs $static::atel_apm_var_prefix
    }

    call atel_telemetry_lib::emit $pairs
}

when ACCESS_POLICY_COMPLETED priority 900 {
    if { !$static::atel_enabled || !$static::atel_apm_completed } { return }

    # post-logon we have the authoritative identity
    if { $static::atel_en(identity) } {
        set u ""
        catch { set u [ACCESS::session data get "session.logon.last.username"] }
        if { $u ne "" } {
            set atel(identity)     $u
            set atel(identity_src) "apm"
        }
    }

    set pairs [list ts [clock seconds] event "apm_policy_completed"]
    if { [info exists atel(_vs)] } { lappend pairs vs $atel(_vs) }
    catch { lappend pairs policy_result [ACCESS::policy result] }
    catch {
        if { $static::atel_debug } {
            lappend pairs sid [ACCESS::session sid]
        } else {
            lappend pairs sid [string range [ACCESS::session sid] 0 7]
        }
    }
    foreach k [lsort [array names atel]] {
        if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
    }

    if { $static::atel_apm_sessionvars } {
        set vpairs [list]
        foreach k [lsort [array names atel]] {
            if { [string index $k 0] ne "_" } { lappend vpairs $k $atel($k) }
        }
        call atel_telemetry_lib::apm_setvars $vpairs $static::atel_apm_var_prefix
    }

    call atel_telemetry_lib::emit $pairs
}

###############################################################################################
#  WAF (ASM/AWAF) violation decoration
#  (requires ASM provisioned; comment this section out otherwise)
###############################################################################################

when ASM_REQUEST_DONE priority 900 {
    if { !$static::atel_enabled } { return }

    # AWAF DeviceID: collect on every inspected request, independent of the
    # violation-decoration gating below.  This event fires after our
    # HTTP_REQUEST record is emitted, so when a device id first appears on a
    # per-flow emission we send a one-time supplemental "device_id" record.
    if { $static::atel_en(device_awaf) && ![info exists atel(device_awaf)] } {
        set fp ""
        catch { set fp [ASM::fingerprint] }
        if { $fp ne "" && $fp ne "0" } {
            set atel(device_awaf) $fp
            if { $static::atel_en(device_awaf) >= 2 || $static::atel_debug } {
                call atel_telemetry_lib::dbg "device_awaf" "fingerprint=$fp"
            }
            if { [info exists atel_emitted] && !$static::atel_emit_per_request } {
                set pairs [list ts [clock seconds] event "device_id"]
                if { [info exists atel(_vs)] } { lappend pairs vs $atel(_vs) }
                foreach k [lsort [array names atel]] {
                    if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
                }
                call atel_telemetry_lib::emit $pairs
            }
        }
    }

    if { !$static::atel_waf_decorate } { return }

    set st ""
    catch { set st [ASM::status] }
    if { $st eq "passed" && !$static::atel_waf_decorate_all } { return }

    set pairs [list ts [clock seconds] event "waf"]
    if { [info exists atel(_vs)] } { lappend pairs vs $atel(_vs) }
    lappend pairs asm_status $st
    catch { lappend pairs support_id [ASM::support_id] }
    catch { lappend pairs violations [join [ASM::violation names] ";"] }
    catch { lappend pairs severity [ASM::severity] }
    foreach k [lsort [array names atel]] {
        if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
    }

    call atel_telemetry_lib::emit $pairs
}

###############################################################################################
#  Bot Defense profile DeviceID
#  (requires a Bot Defense profile; comment this section out otherwise)
###############################################################################################

when BOTDEFENSE_ACTION priority 900 {
    if { !$static::atel_enabled || !$static::atel_en(device_bot) } { return }

    # Device IDs come from the Bot Defense JS challenge, so the first request
    # of a brand-new client legitimately has none; the id shows up once the
    # browser has run the challenge and re-sent.  This event also fires after
    # our HTTP_REQUEST record, so a newly seen id triggers a one-time
    # supplemental "device_id" record in per-flow emission mode.
    set newid 0
    catch {
        set did [BOTDEFENSE::device_id]
        if { $did ne "" && $did ne "0" && ![info exists atel(device_bot)] } {
            set atel(device_bot) $did
            set newid 1
        }
    }
    if { $static::atel_en(device_bot) >= 2 || $static::atel_debug } {
        set act ""
        set rsn ""
        catch { set act [BOTDEFENSE::action] }
        catch { set rsn [BOTDEFENSE::reason] }
        call atel_telemetry_lib::dbg "device_bot" \
            "device_id=[expr {[info exists atel(device_bot)] ? $atel(device_bot) : ""}] action=$act reason=$rsn"
    }
    if { $newid && [info exists atel_emitted] && !$static::atel_emit_per_request } {
        set pairs [list ts [clock seconds] event "device_id"]
        if { [info exists atel(_vs)] } { lappend pairs vs $atel(_vs) }
        foreach k [lsort [array names atel]] {
            if { [string index $k 0] ne "_" } { lappend pairs $k $atel($k) }
        }
        call atel_telemetry_lib::emit $pairs
    }
}
