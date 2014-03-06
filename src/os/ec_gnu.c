/*
    ettercap -- GNU hurd specific functions

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
/* XXX GNU/hurd seems to be NOT supported at this point
   See https://github.com/Ettercap/ettercap/issues/151
   http://www.mail-archive.com/debian-hurd@lists.debian.org/msg21345.html
   These functions are just "stubs" to allow the package build for hurd
   patches are welcome!
*/
#include <ec.h>
void disable_interface_offload(void);

/*******************************************/

void disable_ip_forward(void)
{
   DEBUG_MSG ("disable_ip_forward (no-op)\n");
}

void restore_ip_forward(void)
{
   DEBUG_MSG ("restore_ip_forward (no-op)\n");
}

#ifdef WITH_IPV6
void disable_ipv6_forward(void)
{
   DEBUG_MSG ("disable_ipv6_forward (no-op)\n");
}

void restore_ipv6_forward(void)
{
   DEBUG_MSG ("restore_ipv6_forward (no-op)\n");
}
#endif

u_int16 get_iface_mtu(const char *iface)
{
   (void) iface;
   return 0;
}

void disable_interface_offload(void)
{
}

/* EOF */

// vim:ts=3:expandtab

