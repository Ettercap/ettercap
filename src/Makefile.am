
# $Id: Makefile.am,v 1.55 2003/10/08 20:41:41 alor Exp $

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = ettercap

ettercap_SOURCES = ec_capture.c \
                   ec_checksum.c \
                   ec_conf.c \
                   ec_connbuf.c \
                   ec_conntrack.c \
                   ec_debug.c \
                   ec_decode.c \
                   ec_dispatcher.c \
                   ec_dissect.c \
                   ec_error.c \
                   ec_file.c \
                   ec_filter.c \
                   ec_fingerprint.c \
                   ec_format.c \
                   ec_globals.c \
                   ec_hash.c \
                   ec_hook.c \
                   ec_inet.c \
                   ec_inject.c \
                   ec_log.c \
                   ec_main.c \
                   ec_manuf.c \
                   ec_mitm.c \
                   ec_packet.c \
                   ec_parser.c \
                   ec_passive.c \
                   ec_plugins.c \
                   ec_poll.c \
                   ec_profiles.c \
                   ec_resolv.c \
                   ec_scan.c \
                   ec_send.c \
                   ec_services.c \
                   ec_session.c \
                   ec_signals.c \
                   ec_socket.c \
                   ec_sniff.c \
                   ec_sniff_bridge.c \
                   ec_sniff_unified.c \
                   ec_stats.c \
                   ec_streambuf.c \
                   ec_strings.c \
                   ec_threads.c \
                   ec_ui.c \
                   ec_update.c 

ettercap_SOURCES += interfaces/console/ec_console.c \
                    interfaces/console/ec_console_conn.c \
                    interfaces/console/ec_console_display.c \
                    interfaces/console/ec_console_profile.c \
                    interfaces/console/ec_console_plugin.c
                    
ettercap_SOURCES += interfaces/daemon/ec_daemon.c

if NCURSES
#ettercap_SOURCES += interfaces/ncurses/ec_ncurses.c
endif

if GTK
#ettercap_SOURCES += interfaces/gtk/ec_gtk.c
endif
                    
ettercap_SOURCES += mitm/ec_arp_poisoning.c

ettercap_SOURCES += protocols/ec_eth.c \
				        protocols/ec_wifi.c \
				        protocols/ec_arp.c \
				        protocols/ec_ip.c \
				        protocols/ec_ip6.c \
				        protocols/ec_tcp.c \
				        protocols/ec_udp.c \
				        protocols/ec_icmp.c 
               
if HAVE_DN_EXPAND
ettercap_SOURCES += dissectors/ec_dns.c
endif

ettercap_SOURCES += dissectors/ec_bgp.c \
                    dissectors/ec_cvs.c \
                    dissectors/ec_ftp.c \
				        dissectors/ec_imap.c \
				        dissectors/ec_icq.c \
				        dissectors/ec_irc.c \
				        dissectors/ec_msn.c \
				        dissectors/ec_mysql.c \
				        dissectors/ec_napster.c \
				        dissectors/ec_nntp.c \
				        dissectors/ec_ospf.c \
				        dissectors/ec_pop.c \
				        dissectors/ec_rcon.c \
				        dissectors/ec_rip.c \
				        dissectors/ec_rlogin.c \
				        dissectors/ec_snmp.c \
				        dissectors/ec_socks.c \
				        dissectors/ec_telnet.c \
				        dissectors/ec_vnc.c \
				        dissectors/ec_vrrp.c \
				        dissectors/ec_x11.c 
if OPENSSL
#ettercap_SOURCES += dissectors/ec_https.c \
#                    dissector/ec_ssh.c
endif

### OS dependent

if LINUX
ettercap_SOURCES += os/ec_linux.c
endif
if BSD
ettercap_SOURCES += os/ec_bsd.c
endif
if DARWIN
ettercap_SOURCES += os/ec_darwin.c
endif
if SOLARIS
ettercap_SOURCES += os/ec_solaris.c
endif
if CYGWIN
ettercap_SOURCES += os/ec_cygwin.c
endif


ettercap_CFLAGS = @EC_CFLAGS@

#ettercap_LDADD = @LTLIBOBJS@ @EC_LIBS@ 
ettercap_LDADD = @LIBOBJS@ @EC_LIBS@ 

ettercap_LDFLAGS = -export-dynamic

CLEANFILES = *.log *.out core* missing/*.o *~

## MISSING FUNCTIONS

missing/strlcat.o:
	$(COMPILE) -c missing/strlcat.c -o missing/strlcat.o

missing/strlcpy.o:
	$(COMPILE) -c missing/strlcpy.c -o missing/strlcpy.o
	
missing/strsep.o:
	$(COMPILE) -c missing/strsep.c -o missing/strsep.o
	
missing/strcasestr.o:
	$(COMPILE) -c missing/strcasestr.c -o missing/strcasestr.o
	
missing/scandir.o:
	$(COMPILE) -c missing/scandir.c -o missing/scandir.o
	
missing/memmem.o:
	$(COMPILE) -c missing/memmem.c -o missing/memmem.o
	
missing/memcmp.o:
	$(COMPILE) -c missing/memcmp.c -o missing/memcmp.o
	
missing/getopt.o:
	$(COMPILE) -c missing/getopt.c -o missing/getopt.o
	
missing/getopt_long.o:
	$(COMPILE) -c missing/getopt_long.c -o missing/getopt_long.o
	
# vim:ts=4:noexpandtab
