add_library(arp_cop MODULE arp_cop/arp_cop.c)
set_target_properties(arp_cop PROPERTIES PREFIX "ec_")

add_library(autoadd MODULE autoadd/autoadd.c)
set_target_properties(autoadd PROPERTIES PREFIX "ec_")

add_library(chk_poison MODULE chk_poison/chk_poison.c)
set_target_properties(chk_poison PROPERTIES PREFIX "ec_")

add_library(dns_spoof MODULE dns_spoof/dns_spoof.c)
target_link_libraries(dns_spoof ${HAVE_RESOLV})
set_target_properties(dns_spoof PROPERTIES PREFIX "ec_")

add_library(dos_attack MODULE dos_attack/dos_attack.c)
target_link_libraries(dos_attack ${HAVE_LIBNET})
set_target_properties(dos_attack PROPERTIES PREFIX "ec_")

add_library(dummy MODULE dummy/dummy.c)
set_target_properties(dummy PROPERTIES PREFIX "ec_")

add_library(find_conn MODULE find_conn/find_conn.c)
set_target_properties(find_conn PROPERTIES PREFIX "ec_")

add_library(find_ettercap MODULE find_ettercap/find_ettercap.c)
set_target_properties(find_ettercap PROPERTIES PREFIX "ec_")

add_library(find_ip MODULE find_ip/find_ip.c)
set_target_properties(find_ip PROPERTIES PREFIX "ec_")

add_library(finger MODULE finger/finger.c)
set_target_properties(finger PROPERTIES PREFIX "ec_")

add_library(finger_submit MODULE finger_submit/finger_submit.c)
set_target_properties(finger_submit PROPERTIES PREFIX "ec_")

add_library(gre_relay MODULE gre_relay/gre_relay.c)
set_target_properties(gre_relay PROPERTIES PREFIX "ec_")

add_library(gw_discover MODULE gw_discover/gw_discover.c)
set_target_properties(gw_discover PROPERTIES PREFIX "ec_")

add_library(isolate MODULE isolate/isolate.c)
set_target_properties(isolate PROPERTIES PREFIX "ec_")

add_library(link_type MODULE link_type/link_type.c)
set_target_properties(link_type PROPERTIES PREFIX "ec_")

add_library(nbns_spoof MODULE nbns_spoof/nbns_spoof.c)
set_target_properties(nbns_spoof PROPERTIES PREFIX "ec_")

if(HAVE_PCRE)
    if(CURL_FOUND)
        add_library(sslstrip MODULE sslstrip/sslstrip.c)
        target_link_libraries(sslstrip ${CURL_LIBRARY} ${HAVE_PCRE})
        set_target_properties(sslstrip PROPERTIES PREFIX "ec_")
        set(SSL_STRIP_PLUGIN sslstrip)
    else(CURL_FOUND)
        message(STATUS "Not building sslstrip plugin. Requires libcurl.")
    endif(CURL_FOUND)
else(HAVE_PCRE)
    message(STATUS "Not building sslstrip plugin. Requires pcre.")
endif(HAVE_PCRE)

add_library(pptp_chapms1 MODULE pptp_chapms1/pptp_chapms1.c)
set_target_properties(pptp_chapms1 PROPERTIES PREFIX "ec_")

add_library(pptp_clear MODULE pptp_clear/pptp_clear.c)
set_target_properties(pptp_clear PROPERTIES PREFIX "ec_")

add_library(pptp_pap MODULE pptp_pap/pptp_pap.c)
set_target_properties(pptp_pap PROPERTIES PREFIX "ec_")

add_library(pptp_reneg MODULE pptp_reneg/pptp_reneg.c)
set_target_properties(pptp_reneg PROPERTIES PREFIX "ec_")

add_library(rand_flood MODULE rand_flood/rand_flood.c)
set_target_properties(rand_flood PROPERTIES PREFIX "ec_")

add_library(remote_browser MODULE remote_browser/remote_browser.c)
set_target_properties(remote_browser PROPERTIES PREFIX "ec_")

add_library(reply_arp MODULE reply_arp/reply_arp.c)
set_target_properties(reply_arp PROPERTIES PREFIX "ec_")

add_library(repoison_arp MODULE repoison_arp/repoison_arp.c)
set_target_properties(repoison_arp PROPERTIES PREFIX "ec_")

add_library(scan_poisoner MODULE scan_poisoner/scan_poisoner.c)
set_target_properties(scan_poisoner PROPERTIES PREFIX "ec_")

add_library(search_promisc MODULE search_promisc/search_promisc.c)
set_target_properties(search_promisc PROPERTIES PREFIX "ec_")

add_library(smb_clear MODULE smb_clear/smb_clear.c)
set_target_properties(smb_clear PROPERTIES PREFIX "ec_")

add_library(smb_down MODULE smb_down/smb_down.c)
set_target_properties(smb_down PROPERTIES PREFIX "ec_")

add_library(smurf_attack MODULE smurf_attack/smurf_attack.c)
set_target_properties(smurf_attack PROPERTIES PREFIX "ec_")

add_library(stp_mangler MODULE stp_mangler/stp_mangler.c)
set_target_properties(stp_mangler PROPERTIES PREFIX "ec_")

set(PLUGINS arp_cop
autoadd
chk_poison
dns_spoof
dos_attack
dummy
find_conn
find_ettercap
find_ip
finger
finger_submit
gre_relay
gw_discover
isolate
link_type
nbns_spoof
${SSL_STRIP_PLUGIN}
pptp_chapms1
pptp_clear
pptp_pap
pptp_reneg
rand_flood
remote_browser
reply_arp
repoison_arp
scan_poisoner
search_promisc
smb_clear
smb_down
smurf_attack
stp_mangler)

foreach(plugin ${PLUGINS})
	target_link_libraries(${plugin} ettercap)
endforeach(plugin)

install(TARGETS
            arp_cop
            autoadd
            chk_poison
            dns_spoof
            dos_attack
            dummy
            find_conn
            find_ettercap
            find_ip
            finger
            finger_submit
            gre_relay
            gw_discover
            isolate
            link_type
            nbns_spoof
            ${SSL_STRIP_PLUGIN}
            pptp_chapms1
            pptp_clear
            pptp_pap
            pptp_reneg
            rand_flood
            remote_browser
            reply_arp
            repoison_arp
            scan_poisoner
            search_promisc
            smb_clear
            smb_down
            smurf_attack
            stp_mangler
        LIBRARY DESTINATION ${INSTALL_LIBDIR}/ettercap/
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
