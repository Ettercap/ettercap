
include $(top_srcdir)/Makefile.am.common

sbin_PROGRAMS = ettercap

ettercap_SOURCES = ec_main.c \
				   ec_signals.c \
				   ec_parser.c \
				   ec_globals.c \
				   ec_debug.c \
				   ec_error.c \
				   ec_ui.c \
				   ec_inet.c \
				   ec_resolv.c \
				   ec_checksum.c \
				   ec_threads.c \
				   ec_capture.c \
				   ec_send.c \
				   ec_decode.c \
				   ec_dissect.c \
				   ec_dispatcher.c \
				   ec_packet.c \
				   ec_hook.c \
				   ec_fingerprint.c \
				   ec_passive.c \
				   ec_profiles.c \
				   ec_hash.c \
				   ec_file.c \
				   ec_log.c \
				   ec_manuf.c \
				   ec_services.c \
				   ec_plugins.c \
				   ec_format.c \
				   ec_poll.c \
				   ec_stats.c \
				   ec_scan.c \
				   ec_session.c \
				   ec_sniff.c \
				   ec_sniff_unified.c \
				   ec_sniff_bridge.c \
				   ec_sniff_arp.c \
				   protocols/ec_eth.c \
				   protocols/ec_wifi.c \
				   protocols/ec_arp.c \
				   protocols/ec_ip.c \
				   protocols/ec_ip6.c \
				   protocols/ec_tcp.c \
				   protocols/ec_udp.c \
				   protocols/ec_icmp.c \
				   dissectors/ec_pop.c \
				   dissectors/ec_ftp.c \
				   interfaces/console/ec_console.c \
				   interfaces/console/ec_console_display.c \
				   interfaces/console/ec_console_plugin.c \
				   interfaces/daemon/ec_daemon.c 
               
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

if NCURSES
#ettercap_SOURCES += interfaces/ncurses/ec_ncurses.c
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
