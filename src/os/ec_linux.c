/*
    ettercap -- linux specific functions

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

    $Id: ec_linux.c,v 1.3 2003/10/28 21:10:55 alor Exp $
*/

#include <ec.h>

#include <sys/ioctl.h>
#include <net/if.h>

/* the old value */
static char saved_status;
/* 
 * we need it global, since after the privs dropping
 * we cannot open the file anymode, so we open it 
 * with high privs.
 */
static FILE *fd;

/* protos */

void disable_ip_forward(void);
static void restore_ip_forward(void);
u_int16 get_iface_mtu(char *iface);

/*******************************************/

void disable_ip_forward(void)
{
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");

   fscanf(fd, "%c", &saved_status);
   fclose(fd);

   DEBUG_MSG("disable_ip_forward: old value = %c", saved_status);
  
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");
   
   fprintf(fd, "0");
   
   atexit(restore_ip_forward);
}

static void restore_ip_forward(void)
{
   DEBUG_MSG("ATEXIT: restore_ip_forward: restore to %c", saved_status);

   /* fd is already opened (by disable_ip_forward) */
   fprintf(fd, "%c", saved_status );
   fclose(fd);
}

/* 
 * get the MTU parameter from the interface 
 */
u_int16 get_iface_mtu(char *iface)
{
   int sock, mtu;
   struct ifreq ifr;

   /* open the socket to work on */
   sock = socket(PF_INET, SOCK_DGRAM, 0);
               
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

