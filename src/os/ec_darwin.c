/*
    ettercap -- darwin specific functions

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/os/ec_darwin.c,v 1.2 2003/05/26 20:02:14 alor Exp $
*/

#include <ec.h>

#include <sys/sysctl.h>

static int saved_status;

void disable_ip_forward(void);
static void restore_ip_forward(void);

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
}


static void restore_ip_forward(void)
{
   int mib[4];

   mib[0] = CTL_NET;
   mib[1] = PF_INET;
   mib[2] = IPPROTO_IP;
   mib[3] = IPCTL_FORWARDING;

   if( (sysctl(mib, 4, NULL, NULL, &saved_status, sizeof(saved_status))) == -1)
      FATAL_ERROR("Please restore manually the value of net.inet.ip.forwarding to %d", saved_status);

   DEBUG_MSG("ATEXIT: restore_ip_forward | net.inet.ip.forwarding = %d\n", saved_status);
                        
}


/* EOF */

// vim:ts=3:expandtab

