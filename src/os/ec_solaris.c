/*
    ettercap -- solaris specific functions

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

    $Id: ec_solaris.c,v 1.5 2003/09/18 22:15:04 alor Exp $
*/

#include <ec.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stropts.h>
#include <inet/nd.h>

static char saved_status[2];
/* open it with high privs and use it later */
static int fd;

void disable_ip_forward(void);
static void restore_ip_forward(void);

/*******************************************/

void disable_ip_forward(void)
{
   struct strioctl strIo;
   char buf[65536];
   char *cp;

   cp = "ip_forwarding";
   memset(buf, '\0', sizeof(buf));
   sprintf(buf, "%s", cp);

   if ((fd = open("/dev/ip", O_RDWR)) < 0)
      ERROR_MSG("open failed for /dev/ip");

   strIo.ic_cmd = ND_GET;
   strIo.ic_timout = 0;
   strIo.ic_len = sizeof(buf);
   strIo.ic_dp = buf;

   /* Call IOCTL to return status */

   if ( (ioctl(fd, I_STR, (char *)&strIo)) == -1 )
      ERROR_MSG("ioctl(I_STR)");
 

   if (strIo.ic_cmd == ND_GET) {
      strcpy(saved_status, buf);
                                                      }
   DEBUG_MSG("disable_ip_forward -- previous value = %s", saved_status);

   memset(buf, '\0', sizeof(buf));
   sprintf(buf, "%s", cp);

   /* the format is "element"\0"value"\0 */
   buf[strlen(buf) + 1] = '0';  

   strIo.ic_cmd = ND_SET;
   strIo.ic_timout = 0;
   strIo.ic_len = sizeof(buf);
   strIo.ic_dp = buf;

   if ( (ioctl(fd, I_STR, (char *)&strIo)) == -1 )
      ERROR_MSG("ioctl(I_STR)");

   DEBUG_MSG("Inet_DisableForwarding -- NEW value = 0");

   atexit(restore_ip_forward);
}

static void restore_ip_forward(void)
{
   struct strioctl strIo;
   char buf[65536];
   char *cp;

   /* no need to restore anything */
   if (saved_status[0] == '0')
      return;
   
   cp = "ip_forwarding";
   memset(buf, '\0', sizeof(buf));
   sprintf(buf, "%s", cp);

   /* the format is "element"\0"value"\0 */
   sprintf(buf + strlen(buf)+1, "%s", saved_status);   

   DEBUG_MSG("ATEXIT: restore_ip_forward -- restoring to value = %s", saved_status);

   strIo.ic_cmd = ND_SET;
   strIo.ic_timout = 0;
   strIo.ic_len = sizeof(buf);
   strIo.ic_dp = buf;

   /* Call IOCTL to set the status */
   if ( (ioctl(fd, I_STR, (char *)&strIo)) == -1 )
      FATAL_ERROR("Please restore manually the ip_forwarding value to %s", saved_status);

   close(fd);
                                                
}


/* EOF */

// vim:ts=3:expandtab

