###############################################################################################
#  atel_telemetry_lib  --  Access Telemetry proc library
#
#  Companion library for atel_telemetry_main.tcl.  Contains all reusable telemetry
#  collectors and emitters as procs so the execution iRule stays small and the
#  collectors can be reused by other iRules via:
#
#      call atel_telemetry_lib::<proc> <args...>
#
#  Both iRules must be attached to the same virtual server (this one can be attached
#  anywhere; only the procs are used -- it defines no traffic events of its own
#  other than RULE_INIT).
#
#  JA4 / JA4T / JA4L collectors are adapted from the F5 DevCentral implementations:
#      https://github.com/f5devcentral/f5-ja4
#  JA4 TLS Client Fingerprinting is Open-Source, Licensed under BSD 3-Clause.
#  JA4T / JA4L are Copyright (c) 2024 FoxIO, LLC, Licensed under FoxIO License 1.1.
#  See https://github.com/FoxIO-LLC/ja4 for the spec and full license text.
###############################################################################################

when RULE_INIT {
    # Hard parser limits (DoS guards for attacker-controlled bytes)
    set static::atel_ja4_max_record 17408
    set static::atel_ja4_max_iter   256
    set static::atel_ja4t_max_opts  32
}

###############################################################################################
# ---- generic helpers ------------------------------------------------------------------------
###############################################################################################

# Gated debug logger.  Items log here only when their per-item mode is debug (2)
# or the global debug switch is on -- the caller decides; this just prints.
# Logged at info level on purpose: default syslog filters can drop .debug
# severity, and these lines only exist when debug mode is explicitly enabled.
proc dbg { item msg } {
    log local0. "ATEL($item): $msg"
}

# Loose IPv4/IPv6 validation -- enough to reject header garbage before we feed
# a value to whereis / IP::reputation.
proc valid_ip { ip } {
    if { $ip eq "" } { return 0 }
    if { [regexp {^[0-9]{1,3}(\.[0-9]{1,3}){3}$} $ip] } { return 1 }
    if { [string match "*:*" $ip] && [regexp {^[0-9A-Fa-f:\.]+$} $ip] } { return 1 }
    return 0
}

# Resolve the effective client IP.  When trust_xff is set and the XFF header
# carries a plausible address, the left-most entry wins; otherwise fall back to
# the TCP source address.  Returns:  { <ip> <source: xff|tcp> }
proc effective_ip { conn_ip xff trust } {
    if { $trust && $xff ne "" } {
        set first [string trim [lindex [split $xff ","] 0]]
        # tolerate "ip:port" notation some proxies emit
        if { [regexp {^([0-9]{1,3}(\.[0-9]{1,3}){3}):[0-9]+$} $first junk bare] } {
            set first $bare
        }
        if { [call atel_telemetry_lib::valid_ip $first] } {
            return [list $first "xff"]
        }
    }
    return [list $conn_ip "tcp"]
}

# sha256 -> first 12 hex chars; used to pseudonymize sensitive values (cookies,
# session ids) in standard mode.
proc hash12 { s } {
    if { $s eq "" } { return "" }
    binary scan [sha256 $s] H* h
    return [string range $h 0 11]
}

###############################################################################################
# ---- GEO location (whereis) -----------------------------------------------------------------
###############################################################################################

# Returns a flat key/value list: geo_country, geo_continent, geo_state and, in
# debug mode, geo_city / geo_isp / geo_org when the geolocation data file
# provides them.  Every lookup is catch-wrapped: missing geo DB => empty result.
proc geo { ip debug } {
    set out [list]
    foreach f { country continent state } {
        set v ""
        catch { set v [whereis $ip $f] }
        if { $v ne "" } { lappend out "geo_$f" $v }
    }
    if { $debug } {
        foreach f { city zip isp org } {
            set v ""
            catch { set v [whereis $ip $f] }
            if { $v ne "" } { lappend out "geo_$f" $v }
        }
    }
    return $out
}

###############################################################################################
# ---- IP Intelligence / reputation -----------------------------------------------------------
###############################################################################################

# Returns the IP Intelligence categories for the address joined with ";", or ""
# when the IPI subscription/db is not present (IP::reputation throws -> catch).
proc iprep { ip } {
    set cats ""
    catch { set cats [IP::reputation $ip] }
    return [join $cats ";"]
}

###############################################################################################
# ---- JA4T : TCP fingerprint  (call from FLOW_INIT only) -------------------------------------
#  Adapted from f5devcentral/f5-ja4 ja4t.irule (FoxIO License 1.1)
###############################################################################################

# Must be invoked from FLOW_INIT so DATAGRAM::tcp sees the client SYN.
# Returns "<recv_win>_<opt-list>_<mss>_<win_scale>" or "" on failure.
proc ja4t_collect {} {
    set ja4t ""
    if { [catch {
        set recv_win  [DATAGRAM::tcp window]
        set ops_list  ""
        set opt_count 0
        unset -nocomplain mss
        unset -nocomplain win_scale

        foreach option [DATAGRAM::tcp option] {
            if { [incr opt_count] > $static::atel_ja4t_max_opts } { break }
            # Each option is "kind value-bytes"; split on the first space only
            # so attacker-controlled bytes never hit a regex.
            set sp [string first " " ${option}]
            if { ${sp} < 0 } {
                set kind  ${option}
                set value ""
            } else {
                set kind  [string range ${option} 0 [expr {${sp} - 1}]]
                set value [string range ${option} [expr {${sp} + 1}] end]
            }
            switch ${kind} {
                "2" {
                    if { [string length ${value}] >= 2 } {
                        binary scan ${value} S mss
                        if { [info exists mss] } { set mss [expr {${mss} & 0xffff}] }
                    }
                }
                "3" {
                    if { [string length ${value}] >= 1 } {
                        binary scan ${value} c win_scale
                        if { [info exists win_scale] } { set win_scale [expr {${win_scale} & 0xff}] }
                    }
                }
            }
            append ops_list "${kind}-"
        }
        set ops_list [string trimright ${ops_list} "-"]
        if { ${ops_list} eq "" } { set ops_list "00" }
        if { ![info exists win_scale] } { set win_scale 0 }
        if { ![info exists mss] }       { set mss 0 }

        set ja4t "${recv_win}_${ops_list}_${mss}_${win_scale}"
    } err] } {
        call atel_telemetry_lib::dbg "ja4t" "collect failed: $err"
        set ja4t ""
    }
    return $ja4t
}

###############################################################################################
# ---- JA4 : TLS ClientHello fingerprint ------------------------------------------------------
#  Adapted from f5devcentral/f5-ja4 ja4.irule (JA4 TLS is BSD 3-Clause)
#
#  Pure parser: feed it the buffered TCP payload from CLIENT_DATA; the caller
#  owns TCP::collect / TCP::release.  Returns one of:
#      { need <bytes> }            -- caller should TCP::collect <bytes>
#      { abort }                   -- not a parseable ClientHello, release
#      { done <ja4> <ja4_r> }      -- fingerprints ready, release
###############################################################################################

proc ja4_parse { payload plen } {
    if { $plen < 5 } { return [list need 5] }

    binary scan $payload cH4S content_type proto_ver rlen
    set content_type [expr { $content_type & 0xff }]
    set rlen         [expr { $rlen & 0xffff }]
    set total_needed [expr { $rlen + 5 }]

    if { $content_type != 0x16 } { return [list abort] }
    if { $total_needed > $static::atel_ja4_max_record || $total_needed < 44 } { return [list abort] }
    if { $plen < $total_needed } { return [list need $total_needed] }
    if { $total_needed > $plen } { set total_needed $plen }

    binary scan $payload @5c handshake_type
    set handshake_type [expr { $handshake_type & 0xff }]
    if { $handshake_type != 0x01 } { return [list abort] }

    binary scan $payload @9H4 server_ver
    set ja4_ver  $server_ver
    set ja4_tprt "t"

    set off 43
    if { $off >= $total_needed } { return [list abort] }

    binary scan $payload @${off}c sessid_len
    if { ![info exists sessid_len] } { return [list abort] }
    set sessid_len [expr { $sessid_len & 0xff }]
    set off [expr { $off + 1 + $sessid_len }]
    if { $off + 2 > $total_needed } { return [list abort] }

    binary scan $payload @${off}S cs_length
    set cs_length [expr { $cs_length & 0xffff }]
    incr off 2
    if { $cs_length < 0 || ($cs_length % 2) != 0 || $off + $cs_length > $total_needed } {
        return [list abort]
    }

    set cs_end      [expr { $off + $cs_length }]
    set cipher_list [list]
    set cs_iter 0
    while { $off < $cs_end } {
        if { [incr cs_iter] > $static::atel_ja4_max_iter } { break }
        unset -nocomplain cs_int cs_hex
        binary scan $payload @${off}SH4 cs_int cs_hex
        if { ![info exists cs_hex] || [string length $cs_hex] != 4 } { break }
        set cs_int [expr { $cs_int & 0xffff }]
        incr off 2
        # skip GREASE values (0x?a?a with matching bytes)
        if { ($cs_int & 0x0f0f) == 0x0a0a && (($cs_int >> 8) & 0xff) == ($cs_int & 0xff) } {
            continue
        }
        lappend cipher_list $cs_hex
    }
    set off $cs_end

    if { $off + 1 > $total_needed } { return [list abort] }
    binary scan $payload @${off}c comp_len
    set comp_len [expr { $comp_len & 0xff }]
    set off [expr { $off + 1 + $comp_len }]
    if { $off > $total_needed } { return [list abort] }

    set has_sni   0
    set alpn_val  "00"
    set siga_list [list]
    set ext_list  [list]

    if { $off + 2 <= $total_needed } {
        binary scan $payload @${off}S ext_total_len
        set ext_total_len [expr { $ext_total_len & 0xffff }]
        incr off 2
        if { $ext_total_len < 0 || $off + $ext_total_len > $total_needed } { return [list abort] }
        set ext_end [expr { $off + $ext_total_len }]

        set ext_iter 0
        while { $off + 4 <= $ext_end } {
            if { [incr ext_iter] > $static::atel_ja4_max_iter } { break }

            unset -nocomplain et_int et_hex
            binary scan $payload @${off}SH4 et_int et_hex
            if { ![info exists et_hex] || [string length $et_hex] != 4 } { break }
            set et_int [expr { $et_int & 0xffff }]
            incr off 2

            binary scan $payload @${off}S et_len
            set et_len [expr { $et_len & 0xffff }]
            incr off 2

            set data_start $off
            if { $et_len < 0 || $data_start + $et_len > $ext_end } { break }

            if { ($et_int & 0x0f0f) == 0x0a0a && (($et_int >> 8) & 0xff) == ($et_int & 0xff) } {
                set off [expr { $data_start + $et_len }]
                continue
            }

            lappend ext_list $et_hex

            switch $et_hex {
                "0000" {
                    set has_sni 1
                }
                "000d" {
                    if { $et_len >= 2 } {
                        binary scan $payload @${data_start}S sa_len
                        set sa_len [expr { $sa_len & 0xffff }]
                        if { $sa_len >= 0 && ($sa_len % 2) == 0 && $sa_len + 2 <= $et_len } {
                            set sa_off [expr { $data_start + 2 }]
                            set sa_end [expr { $sa_off + $sa_len }]
                            set sa_iter 0
                            while { $sa_off + 2 <= $sa_end } {
                                if { [incr sa_iter] > $static::atel_ja4_max_iter } { break }
                                unset -nocomplain sa_int sa_hex
                                binary scan $payload @${sa_off}SH4 sa_int sa_hex
                                if { ![info exists sa_hex] || [string length $sa_hex] != 4 } { break }
                                set sa_int [expr { $sa_int & 0xffff }]
                                incr sa_off 2
                                if { ($sa_int & 0x0f0f) == 0x0a0a && (($sa_int >> 8) & 0xff) == ($sa_int & 0xff) } {
                                    continue
                                }
                                lappend siga_list $sa_hex
                            }
                        }
                    }
                }
                "0010" {
                    if { $et_len >= 4 } {
                        binary scan $payload @[expr {$data_start + 2}]c alpn_str_len
                        set alpn_str_len [expr { $alpn_str_len & 0xff }]
                        if { $alpn_str_len > 0 && $alpn_str_len + 3 <= $et_len } {
                            binary scan $payload @[expr {$data_start + 3}]a${alpn_str_len} alpn_str
                            binary scan $payload @[expr {$data_start + 3}]H[expr {$alpn_str_len * 2}] alpn_hex
                            set alen [string length $alpn_str]
                            if { $alen >= 1 } {
                                set first_byte [scan [string index $alpn_str 0] %c]
                                set last_byte  [scan [string index $alpn_str end] %c]
                                set first_ok [expr {
                                    ($first_byte >= 0x30 && $first_byte <= 0x39) ||
                                    ($first_byte >= 0x41 && $first_byte <= 0x5A) ||
                                    ($first_byte >= 0x61 && $first_byte <= 0x7A)
                                }]
                                set last_ok [expr {
                                    ($last_byte >= 0x30 && $last_byte <= 0x39) ||
                                    ($last_byte >= 0x41 && $last_byte <= 0x5A) ||
                                    ($last_byte >= 0x61 && $last_byte <= 0x7A)
                                }]
                                if { $first_ok && $last_ok } {
                                    set alpn_val "[string index $alpn_str 0][string index $alpn_str end]"
                                } else {
                                    set alpn_val "[string index $alpn_hex 0][string index $alpn_hex end]"
                                }
                            }
                        }
                    }
                }
                "0027" {
                    set ja4_tprt "q"
                }
                "002b" {
                    if { $et_len >= 1 } {
                        binary scan $payload @${data_start}c sv_len
                        set sv_len [expr { $sv_len & 0xff }]
                        if { $sv_len >= 0 && ($sv_len % 2) == 0 && $sv_len + 1 <= $et_len } {
                            set sv_off [expr { $data_start + 1 }]
                            set sv_end [expr { $sv_off + $sv_len }]
                            set sv_list [list]
                            set sv_iter 0
                            while { $sv_off + 2 <= $sv_end } {
                                if { [incr sv_iter] > $static::atel_ja4_max_iter } { break }
                                unset -nocomplain sv_int sv_hex
                                binary scan $payload @${sv_off}SH4 sv_int sv_hex
                                if { ![info exists sv_hex] || [string length $sv_hex] != 4 } { break }
                                set sv_int [expr { $sv_int & 0xffff }]
                                incr sv_off 2
                                if { ($sv_int & 0x0f0f) == 0x0a0a && (($sv_int >> 8) & 0xff) == ($sv_int & 0xff) } {
                                    continue
                                }
                                lappend sv_list $sv_hex
                            }
                            set sv_list [lsort $sv_list]
                            if { [llength $sv_list] > 0 } {
                                set ja4_ver [lindex $sv_list end]
                            }
                        }
                    }
                }
            }

            set off [expr { $data_start + $et_len }]
        }
    }

    set ja4_sni [expr { $has_sni ? "d" : "i" }]

    set cc [llength $cipher_list]
    if { $cc > 99 } { set cc 99 }
    set ja4_ccnt [format "%02d" $cc]

    set ec [llength $ext_list]
    if { $ec > 99 } { set ec 99 }
    set ja4_ecnt [format "%02d" $ec]

    switch $ja4_ver {
        "0304"  { set ja4_ver "13" }
        "0303"  { set ja4_ver "12" }
        "0302"  { set ja4_ver "11" }
        "0301"  { set ja4_ver "10" }
        "0300"  { set ja4_ver "s3" }
        "0200"  { set ja4_ver "s2" }
        "0100"  { set ja4_ver "s1" }
        "feff"  { set ja4_ver "d1" }
        "fefd"  { set ja4_ver "d2" }
        "fefc"  { set ja4_ver "d3" }
        default { set ja4_ver "00" }
    }

    set ja4_a "${ja4_tprt}${ja4_ver}${ja4_sni}${ja4_ccnt}${ja4_ecnt}${alpn_val}"

    set cipher_str [join [lsort $cipher_list] ","]
    if { $cipher_str eq "" } {
        set ja4_b "000000000000"
    } else {
        binary scan [sha256 $cipher_str] H* cipher_hash
        set ja4_b [string range $cipher_hash 0 11]
    }

    set ext_for_hash [list]
    foreach e $ext_list {
        if { $e ne "0000" && $e ne "0010" } { lappend ext_for_hash $e }
    }
    set ext_str  [join [lsort $ext_for_hash] ","]
    set siga_str [join $siga_list ","]
    if { $siga_str ne "" } {
        set hash_input "${ext_str}_${siga_str}"
    } else {
        set hash_input $ext_str
    }
    if { $ext_str eq "" && $siga_str eq "" } {
        set ja4_c "000000000000"
    } else {
        binary scan [sha256 $hash_input] H* ext_hash
        set ja4_c [string range $ext_hash 0 11]
    }

    return [list done "${ja4_a}_${ja4_b}_${ja4_c}" "${ja4_a}_${cipher_str}_${hash_input}"]
}

###############################################################################################
# ---- JA4H : HTTP request fingerprint --------------------------------------------------------
#  Implemented per the FoxIO JA4H spec (https://github.com/FoxIO-LLC/ja4).
#  Call from HTTP_REQUEST only.
###############################################################################################

# Returns { <ja4h> <ja4h_r> }; ja4h_r is "" unless debug is true.
proc ja4h_collect { debug } {
    # a: method(2) + version(2) + cookie c/n + referer r/n + hdr count(2) + accept-language(4)
    set m [string range [string tolower [HTTP::method]] 0 1]
    if { [string length $m] < 2 } { append m "0" }

    set ver [string map {"." ""} [HTTP::version]]
    if { [string length $ver] == 1 } { append ver "0" }
    set ver [string range $ver 0 1]

    set hdr_names   [list]
    set has_cookie  "n"
    set has_referer "n"
    foreach h [HTTP::header names] {
        set hl [string tolower $h]
        if { $hl eq "cookie" }  { set has_cookie "c";  continue }
        if { $hl eq "referer" } { set has_referer "r"; continue }
        lappend hdr_names $hl
    }
    set hc [llength $hdr_names]
    if { $hc > 99 } { set hc 99 }

    set lang "0000"
    set alv [HTTP::header value "Accept-Language"]
    if { $alv ne "" } {
        set alv [string tolower [lindex [split $alv ",;"] 0]]
        set alv [string map {"-" "" "_" "" " " ""} $alv]
        set lang [string range "${alv}0000" 0 3]
    }

    set ja4h_a "${m}${ver}${has_cookie}${has_referer}[format "%02d" $hc]${lang}"

    # b: header names in received order (cookie/referer excluded)
    set hdr_str [join $hdr_names ","]
    set ja4h_b "000000000000"
    if { $hdr_str ne "" } { set ja4h_b [call atel_telemetry_lib::hash12 $hdr_str] }

    # c/d: sorted cookie names / sorted cookie name=value
    set ck_names [list]
    set ck_kv    [list]
    if { $has_cookie eq "c" } {
        catch {
            foreach cn [HTTP::cookie names] {
                lappend ck_names $cn
                lappend ck_kv "${cn}=[HTTP::cookie value $cn]"
            }
        }
    }
    set c_str [join [lsort $ck_names] ","]
    set d_str [join [lsort $ck_kv] ","]
    set ja4h_c "000000000000"
    set ja4h_d "000000000000"
    if { $c_str ne "" } { set ja4h_c [call atel_telemetry_lib::hash12 $c_str] }
    if { $d_str ne "" } { set ja4h_d [call atel_telemetry_lib::hash12 $d_str] }

    set ja4h "${ja4h_a}_${ja4h_b}_${ja4h_c}_${ja4h_d}"
    set ja4h_r ""
    if { $debug } {
        set ja4h_r "${ja4h_a}_${hdr_str}_${c_str}"
    }
    return [list $ja4h $ja4h_r]
}

###############################################################################################
# ---- user identity extraction ---------------------------------------------------------------
###############################################################################################

# Authorization: Basic -- returns the username only; the password is never
# stored or logged.
proc identity_basic { authval } {
    if { ![string match -nocase "basic *" $authval] } { return "" }
    set b64 [string trim [string range $authval 6 end]]
    set dec ""
    if { [catch { set dec [b64decode $b64] }] || $dec eq "" } { return "" }
    return [lindex [split $dec ":"] 0]
}

# base64url decode (JWT segments)
proc b64url_decode { s } {
    set s [string map {- + _ /} $s]
    switch [expr {[string length $s] % 4}] {
        2 { append s "==" }
        3 { append s "=" }
        1 { return "" }
    }
    set out ""
    catch { set out [b64decode $s] }
    return $out
}

# Authorization: Bearer <jwt> -- decodes the JWT payload (no signature
# validation; telemetry only) and returns the requested string claim.
proc identity_bearer { authval claim } {
    if { ![string match -nocase "bearer *" $authval] } { return "" }
    set tok   [string trim [string range $authval 7 end]]
    set parts [split $tok "."]
    if { [llength $parts] < 2 } { return "" }
    set payload [call atel_telemetry_lib::b64url_decode [lindex $parts 1]]
    if { $payload eq "" } { return "" }
    set val ""
    regexp -- "\"$claim\"\\s*:\\s*\"(\[^\"\]*)\"" $payload junk val
    return $val
}

###############################################################################################
# ---- record formatting & emission ------------------------------------------------------------
###############################################################################################

proc json_escape { s } {
    return [string map {\\ \\\\ \" \\\" \n \\n \r \\r \t \\t} $s]
}

# pairs = flat {key value key value ...} list; fmt = "json" | "kv"
proc fmt_record { pairs fmt } {
    set items [list]
    if { $fmt eq "json" } {
        foreach {k v} $pairs {
            lappend items "\"[call atel_telemetry_lib::json_escape $k]\":\"[call atel_telemetry_lib::json_escape $v]\""
        }
        return "\{[join $items ","]\}"
    }
    foreach {k v} $pairs {
        set v [string map {\" ' \n " " \r " "} $v]
        lappend items "$k=\"$v\""
    }
    return [join $items " "]
}

# Store one record in the session table for the (future) iApps LX dashboard.
# A monotonically increasing sequence number in <subtable>_meta/seq doubles as
# the record key, so the dashboard can page through records in order, and lets
# us drop the oldest entry once max is exceeded (cheap ring-buffer behavior).
proc table_store { record subtable ttl max } {
    if { [catch {
        set seq [table incr -subtable "${subtable}_meta" "seq"]
        table set -subtable $subtable [format "%012d" $seq] $record $ttl $ttl
        if { $max > 0 && $seq > $max } {
            table delete -subtable $subtable [format "%012d" [expr {$seq - $max}]]
        }
    } err] } {
        call atel_telemetry_lib::dbg "table" "store failed: $err"
    }
}

# Central emitter: formats once, then fans out to HSL, the local table, and
# (optionally) /var/log/ltm based on the static:: switches set by the main
# iRule.  Safe to call from any client-side event.  Returns the record string.
proc emit { pairs } {
    set rec [call atel_telemetry_lib::fmt_record $pairs $static::atel_record_format]

    if { $static::atel_emit_hsl && $static::atel_hsl_pool ne "" } {
        if { [catch {
            set h [HSL::open -proto $static::atel_hsl_proto -pool $static::atel_hsl_pool]
            HSL::send $h "$rec\n"
        } err] } {
            call atel_telemetry_lib::dbg "hsl" "send failed: $err"
        }
    }

    if { $static::atel_emit_table } {
        call atel_telemetry_lib::table_store $rec $static::atel_table_name $static::atel_table_ttl $static::atel_table_max
    }

    if { $static::atel_log_local } {
        log local0.info "ATEL $rec"
    }

    return $rec
}

# Push telemetry into APM session variables (session.custom.atel.* by default)
# so the values are usable inside the access policy (branch rules, logging
# agents, irule-event agents).  catch-wrapped per variable: a missing/expired
# session is a no-op, never an error.
proc apm_setvars { pairs prefix } {
    foreach {k v} $pairs {
        catch { ACCESS::session data set "${prefix}${k}" $v }
    }
}
