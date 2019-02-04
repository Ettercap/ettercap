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

*/

#include <ec.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>

/* the old value */
static char saved_status;
#ifdef WITH_IPV6
static char saved_status_v6_global, saved_status_v6_iface;
#endif

/* protos */

/*******************************************/

void disable_ip_forward(void)
{
   FILE *fd;
   
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");

   fscanf(fd, "%c", &saved_status);
   fclose(fd);

   DEBUG_MSG("disable_ip_forward: old value = %c", saved_status);
 
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");
   
   fprintf(fd, "0");
   fclose(fd);
   
   atexit(restore_ip_forward);
   atexit(regain_privs_atexit);
}

void restore_ip_forward(void)
{
   FILE *fd;
   char current_status;
   
   /* no modification needed */
   if (saved_status == '0')
      return;
   
   if (getuid()) {
      DEBUG_MSG("ATEXIT: restore_ip_forward: cannot restore ip_forward "
                 "since the privileges have been dropped to non root\n");
      FATAL_ERROR("ip_forwarding was disabled, but we cannot re-enable it now.\n"
                  "remember to re-enable it manually\n");
      return;
   }
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");

   fscanf(fd, "%c", &current_status);
   fclose(fd);
   
   DEBUG_MSG("ATEXIT: restore_ip_forward: curr: %c saved: %c", current_status, saved_status);

   if (current_status == saved_status) {
      DEBUG_MSG("ATEXIT: restore_ip_forward: does not need restoration");
      return;
   }

   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   if (fd == NULL) {
      FATAL_ERROR("ip_forwarding was disabled, but we cannot re-enable it now.\n"
                  "remember to re-enable it manually\n");
      return;
   }

   fprintf(fd, "%c", saved_status);
   fclose(fd);

   DEBUG_MSG("ATEXIT: restore_ip_forward: restore to %c", saved_status);

}

#ifdef WITH_IPV6
void disable_ipv6_forward(void)
{
   FILE *fd;
   char fpath_global[] = "/proc/sys/net/ipv6/conf/all/forwarding";
   char fpath_iface[64];
   
   /* global configuration */
   fd = fopen(fpath_global, "r");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_global);
   
   fscanf(fd, "%c", &saved_status_v6_global);
   fclose(fd);

   /* interface specific configuration */
   snprintf(fpath_iface, 63, "/proc/sys/net/ipv6/conf/%s/forwarding", EC_GBL_OPTIONS->iface);

   fd = fopen(fpath_iface, "r");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_iface);
   
   fscanf(fd, "%c", &saved_status_v6_iface);
   fclose(fd);

   fd = fopen(fpath_global, "w");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_global);

   fprintf(fd, "0");
   fclose(fd);

   fd = fopen(fpath_iface, "w");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_iface);

   fprintf(fd, "0");
   fclose(fd);

   DEBUG_MSG("disable_ipv6_forward: old value = %c/%c (global/interface %s)", 
         saved_status_v6_global, saved_status_v6_iface, EC_GBL_OPTIONS->iface);
 
   
   atexit(restore_ipv6_forward);
}

void restore_ipv6_forward(void)
{
   FILE *fd;
   char current_status_global, current_status_iface;
   char fpath_global[] = "/proc/sys/net/ipv6/conf/all/forwarding";
   char fpath_iface[64];
   
   /* no modification needed */
   if (saved_status_v6_global == '0' && saved_status_v6_iface == '0')
      return;
   
   if (getuid()) {
      DEBUG_MSG("ATEXIT: restore_ipv6_forward: cannot restore ipv6_forward "
                 "since the privileges have been dropped to non root\n");
      FATAL_ERROR("ipv6_forwarding was disabled, but we cannot re-enable it now.\n"
                  "remember to re-enable it manually\n");
      return;
   }
   
   /* global configuration */
   fd = fopen(fpath_global, "r");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_global);

   fscanf(fd, "%c", &current_status_global);
   fclose(fd);
   
   /* interface specific configuration */
   snprintf(fpath_iface, 63, "/proc/sys/net/ipv6/conf/%s/forwarding", EC_GBL_OPTIONS->iface);

   fd = fopen(fpath_iface, "r");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_iface);

   fscanf(fd, "%c", &current_status_iface);
   fclose(fd);
   
   DEBUG_MSG("ATEXIT: restore_ipv6_forward: curr: %c/%c saved: %c/%c (global/interface %s)", 
         current_status_global, current_status_iface, 
         saved_status_v6_global, saved_status_v6_iface, EC_GBL_OPTIONS->iface);

   if (current_status_global == saved_status_v6_global && 
         current_status_iface == saved_status_v6_iface) {
      DEBUG_MSG("ATEXIT: restore_ipv6_forward: does not need restoration");
      return;
   }

   /* write back global configuration */
   if ((fd = fopen(fpath_global, "w")) != NULL) {
      fprintf(fd, "%c", saved_status_v6_global);
      fclose(fd);

      DEBUG_MSG("ATEXIT: restore_ipv6_forward: restore global to %c", saved_status_v6_global);
   } else {
      FATAL_ERROR("global ipv6_forwarding was disabled, but we cannot re-enable it now.\n"
                  "remember to re-enable it manually\n");
   }


   /* write back interface specific configuration */
   if ((fd = fopen(fpath_iface, "w")) != NULL) {
      fprintf(fd, "%c", saved_status_v6_iface);
      fclose(fd);

      DEBUG_MSG("ATEXIT: restore_ipv6_forward: restore %s to %c", 
            EC_GBL_OPTIONS->iface, saved_status_v6_iface);
   } else {
      FATAL_ERROR("interface ipv6_forwarding was disabled, but we cannot re-enable it now.\n"
                  "remember to re-enable it manually\n");
   }

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
   if (sock == -1) /* unable to bind to socket, kaboom */
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


/*
 * disable segmentation offload on interface
 * this prevents L3 send errors (payload too large)
 */
void disable_interface_offload(void)
{
	int param_length= 0;
	char *command;
	char **param = NULL;
	char *p;
	int ret_val, i = 0;

	SAFE_CALLOC(command, 100, sizeof(char));

	BUG_IF(command==NULL);

	memset(command, '\0', 100);	
	snprintf(command, 99, "ethtool -K %s tso off gso off gro off lro off", EC_GBL_OPTIONS->iface);

	DEBUG_MSG("disable_interface_offload: Disabling offload on %s", EC_GBL_OPTIONS->iface);

	for(p = strsep(&command, " "); p != NULL; p = strsep(&command, " ")) {
		SAFE_REALLOC(param, (i+1) * sizeof(char *));
		param[i++] = strdup(p);	
	}

	SAFE_REALLOC(param, (i+1) * sizeof(char *));
	param[i] = NULL;
	param_length= i + 1; //because there is a SAFE_REALLOC after the for.

	switch(fork()) {
		case 0:
#ifndef DEBUG
			/* don't print on console if the ethtool cannot disable some offloads unless you are in debug mode */
			close(2);
#endif
			execvp(param[0], param);
			WARN_MSG("cannot disable offload on %s, do you have ethtool installed?", EC_GBL_OPTIONS->iface);
			safe_free_mem(param, &param_length, command);
			_exit(-E_INVALID);
		case -1:
			safe_free_mem(param, &param_length, command);
         break;
		default:
			safe_free_mem(param, &param_length, command);
			wait(&ret_val);
	} 	
}

#ifdef WITH_IPV6
/* 
 * if privacy extension for IPv6 is enabled, under certain
 * circumstances, an IPv6 socket can not be written exiting with
 * code -1 bytes written (Cannot assign requested address).
 * see pull request #245.(https://github.com/Ettercap/ettercap/pull/245) 
 * 
 * this usually happens after returning from hibernation
 * therefore we should warn users.
 * 
 * however investigation of the root cause continues but as long as 
 * it isn't identified and fixed, this function is being kept.
 */
void check_tempaddr(const char *iface)
{
   FILE *fd;
   int mode_global, mode_iface;
   char fpath_global[] = "/proc/sys/net/ipv6/conf/all/use_tempaddr";
   char fpath_iface[64];

   snprintf(fpath_iface, 63, "/proc/sys/net/ipv6/conf/%s/use_tempaddr", iface);
   
   fd = fopen(fpath_global, "r");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_global);

   mode_global = fgetc(fd);
   ON_ERROR(mode_global, EOF, "failed to read value from %s", fpath_global);

   fclose(fd);

   DEBUG_MSG("check_tempaddr: %s = %c", fpath_global, mode_global);
 
   fd = fopen(fpath_iface, "r");
   ON_ERROR(fd, NULL, "failed to open %s", fpath_iface);

   mode_iface = fgetc(fd);
   ON_ERROR(mode_iface, EOF, "failed to read value from %s", fpath_iface);
   
   fclose(fd);
   
   DEBUG_MSG("check_tempaddr: %s = %c", fpath_iface, mode_iface);

   if (mode_global != '0')
      USER_MSG("Ettercap might not work correctly. %s is not set to 0.\n", 
            fpath_global);
 
   if (mode_iface != '0')
      USER_MSG("Ettercap might not work correctly. %s is not set to 0.\n", 
            fpath_iface);

}
#endif

/* EOF */

// vim:ts=3:expandtab

