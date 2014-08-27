/*
    ettercap -- bsd specific functions

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id$
*/

#include <ec.h>

#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sysctl.h>

#include <sys/ioctl.h>
#include <net/if.h>

static int saved_status;
#ifdef WITH_IPV6
static int saved_status_v6;
#endif

/*******************************************/

void disable_ip_forward(void)
{
   int mib[4]; 
   int val = 0;
   size_t len;

   mib[0] = CTL_NET;
   mib[1] = PF_INET;
   mib[2] = IPPROTO_IP;
   mib[3] = IPCTL_FORWARDING;

   len = sizeof(saved_status);

   if( (sysctl(mib, 4, &saved_status, &len, &val, sizeof(val))) == -1)
      ERROR_MSG("sysctl() | net.inet.ip.forwarding");

   DEBUG_MSG("disable_ip_forward | net.inet.ip.forwarding = %d  old_value = %d\n", val, saved_status);
  
   atexit(restore_ip_forward);
   atexit(regain_privs_atexit);
}


void restore_ip_forward(void)
{
   int mib[4];

   mib[0] = CTL_NET;
   mib[1] = PF_INET;
   mib[2] = IPPROTO_IP;
   mib[3] = IPCTL_FORWARDING;

   /* no need to restore anything */
   if (saved_status == 0)
      return;
   
   /* restore the old value */
   if( (sysctl(mib, 4, NULL, NULL, &saved_status, sizeof(saved_status))) == -1)
      FATAL_ERROR("Please restore manually the value of net.inet.ip.forwarding to %d", saved_status);

   DEBUG_MSG("ATEXIT: restore_ip_forward | net.inet.ip.forwarding = %d\n", saved_status);
                        
}

#ifdef WITH_IPV6
void disable_ipv6_forward(void)
{
   int mib[4]; 
   int val = 0;
   size_t len;

   mib[0] = CTL_NET;
   mib[1] = PF_INET6;
   mib[2] = IPPROTO_IPV6;
   mib[3] = IPV6CTL_FORWARDING;

   len = sizeof(saved_status_v6);

   if( (sysctl(mib, 4, &saved_status_v6, &len, &val, sizeof(val))) == -1)
      ERROR_MSG("sysctl() | net.inet6.ip6.forwarding");

   DEBUG_MSG("disable_ipv6_forward | net.inet6.ip6.forwarding = %d  old_value = %d\n", 
         val, saved_status_v6);
  
   atexit(restore_ipv6_forward);
}


void restore_ipv6_forward(void)
{
   int mib[4];

   mib[0] = CTL_NET;
   mib[1] = PF_INET6;
   mib[2] = IPPROTO_IPV6;
   mib[3] = IPV6CTL_FORWARDING;

   /* no need to restore anything */
   if (saved_status_v6 == 0)
      return;
   
   /* restore the old value */
   if( (sysctl(mib, 4, NULL, NULL, &saved_status_v6, sizeof(saved_status_v6))) == -1)
      FATAL_ERROR("Please restore manually the value of net.inet6.ip6.forwarding to %d", 
            saved_status_v6);

   DEBUG_MSG("ATEXIT: restore_ipv6_forward | net.inet6.ip6.forwarding = %d\n", 
         saved_status_v6);
                        
}
#endif

/* 
 * get the MTU parameter from the interface 
 */
u_int16 get_iface_mtu(const char *iface)
{
   int sock, mtu;
   struct ifreq ifr;

   /* open the socket to work on */
   sock = socket(PF_INET, SOCK_DGRAM, 0);
   if (sock == -1)
      FATAL_ERROR("Unable to open socket on interface for MTU query\n");               
   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
                        
   /* get the MTU */
   if ( ioctl(sock, SIOCGIFMTU, &ifr) < 0)  {
      DEBUG_MSG("get_iface_mtu: MTU FAILED... assuming 1500");
      mtu = 1500;
   } else {
      DEBUG_MSG("get_iface_mtu: %d", ifr.ifr_mtu);
      mtu = ifr.ifr_mtu;
   }
   
   close(sock);
   
   return mtu;
}

/* EOF */

// vim:ts=3:expandtab

