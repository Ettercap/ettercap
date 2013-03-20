set(EC_SRC
        ec_capture.c
        ec_checksum.c
        ec_conf.c
        ec_connbuf.c
        ec_conntrack.c
        ec_debug.c
        ec_decode.c
        ec_dispatcher.c
        ec_dissect.c
        ec_error.c
        ec_file.c
        ec_filter.c
        ec_fingerprint.c
        ec_format.c
        ec_globals.c
        ec_hash.c
        ec_hook.c
        ec_inet.c
        ec_inject.c
        ec_interfaces.c
        ec_log.c
        ec_main.c
        ec_manuf.c
        ec_mitm.c
        ec_network.c
        ec_packet.c
        ec_parser.c
        ec_passive.c
        ec_plugins.c
        ec_poll.c
        ec_profiles.c
        ec_resolv.c
        ec_scan.c
        ec_send.c
        ec_services.c
        ec_session.c
        ec_signals.c
        ec_sniff_bridge.c
        ec_sniff.c
        ec_sniff_unified.c
        ec_socket.c
        ec_sslwrap.c
        ec_stats.c
        ec_streambuf.c
        ec_strings.c
        ec_threads.c
        ec_ui.c
        ec_update.c

        dissectors/ec_bgp.c
        dissectors/ec_cvs.c
        dissectors/ec_dhcp.c
        dissectors/ec_ftp.c
        dissectors/ec_http.c
        dissectors/ec_icq.c
        dissectors/ec_imap.c
        dissectors/ec_irc.c
        dissectors/ec_iscsi.c
        dissectors/ec_ldap.c
        dissectors/ec_mdns.c
        dissectors/ec_mongodb.c
        dissectors/ec_mountd.c
        dissectors/ec_msn.c
        dissectors/ec_mysql.c
        dissectors/ec_napster.c
        dissectors/ec_nbns.c
        dissectors/ec_nntp.c
        dissectors/ec_o5logon.c
        dissectors/ec_ospf.c
        dissectors/ec_pop.c
        dissectors/ec_postgresql.c
        dissectors/ec_portmap.c
        dissectors/ec_radius.c
        dissectors/ec_rcon.c
        dissectors/ec_rip.c
        dissectors/ec_rlogin.c
        dissectors/ec_smb.c
        dissectors/ec_smtp.c
        dissectors/ec_snmp.c
        dissectors/ec_socks.c
        dissectors/ec_telnet.c
        dissectors/ec_TN3270.c
        dissectors/ec_vnc.c
        dissectors/ec_vrrp.c
        dissectors/ec_x11.c
        dissectors/ec_ymsg.c

        mitm/ec_arp_poisoning.c
        mitm/ec_dhcp_spoofing.c
        mitm/ec_icmp_redirect.c
        mitm/ec_port_stealing.c

        protocols/ec_arp.c
        protocols/ec_cooked.c
        protocols/ec_eth.c
        protocols/ec_fddi.c
        protocols/ec_gre.c
        protocols/ec_icmp.c
        protocols/ec_ip.c
        protocols/ec_ppi.c
        protocols/ec_ppp.c
        protocols/ec_prism.c
        protocols/ec_radiotap.c
        protocols/ec_rawip.c
        protocols/ec_tcp.c
        protocols/ec_tr.c
        protocols/ec_udp.c
        protocols/ec_vlan.c
        protocols/ec_wifi.c
)

if(ENABLE_IPV6)
    set(EC_SRC ${EC_SRC} protocols/ec_icmp6.c protocols/ec_ip6.c mitm/ec_ip6nd_poison.c)
endif(ENABLE_IPV6)

if(HAVE_DN_EXPAND)
    set(EC_SRC ${EC_SRC} dissectors/ec_dns.c)
endif(HAVE_DN_EXPAND)

if(ENABLE_SSL)
   set(EC_SRC ${EC_SRC} dissectors/ec_ssh.c)
   set(EC_SRC ${EC_SRC} dissectors/ec_gg.c)
endif(ENABLE_SSL)

if(OS_LINUX)
    set(EC_SRC ${EC_SRC} os/ec_linux.c)
elseif(OS_BSD)
    set(EC_SRC ${EC_SRC} os/ec_bsd.c)
elseif(OS_DARWIN)
    set(EC_SRC ${EC_SRC} os/ec_darwin.c)
elseif(OS_MINGW)
    set(EC_SRC ${EC_SRC} os/ec_mingw.c)
elseif(OS_SOLARIS)
    set(EC_SRC ${EC_SRC} os/ec_solaris.c)
endif()

if(NOT HAVE_STRLCAT)
    set(EC_SRC ${EC_SRC} missing/strlcat.c)
endif(NOT HAVE_STRLCAT)
if(NOT HAVE_STRLCPY)
    set(EC_SRC ${EC_SRC} missing/strlcpy.c)
endif(NOT HAVE_STRLCPY)
if(NOT HAVE_STRSEP)
    set(EC_SRC ${EC_SRC} missing/strsep.c)
endif(NOT HAVE_STRSEP)
if(NOT HAVE_STRCASESTR)
    set(EC_SRC ${EC_SRC} missing/strcasestr.c)
endif(NOT HAVE_STRCASESTR)
if(NOT HAVE_MEMMEM)
    set(EC_SRC ${EC_SRC} missing/memmem.c)
endif(NOT HAVE_MEMMEM)
if(NOT HAVE_BASENAME)
    set(EC_SRC ${EC_SRC} missing/basename.c)
endif(NOT HAVE_BASENAME)

add_subdirectory(interfaces)

add_executable(ettercap ${EC_SRC})
target_link_libraries(ettercap ec_interfaces ${EC_LIBS})
set_target_properties(ettercap PROPERTIES ENABLE_EXPORTS TRUE)
install(TARGETS ettercap DESTINATION ${INSTALL_BINDIR})
