/*
    ettercap -- packet object handling

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

    $Id: ec_packet.c,v 1.2 2003/03/10 16:04:53 alor Exp $
*/

#include <ec.h>
#include <ec_packet.h>
#include <ec_inet.h>
#include <ec_ui.h>

/* protos... */

int packet_create_object(struct packet_object **po, u_char *buf, size_t len);
int packet_disp_data(struct packet_object *po, u_char *buf, size_t len);
int packet_destroy_object(struct packet_object **po);
int packet_duplicate(struct packet_object *po, char level, u_char **buf);

void packet_print(struct packet_object *po);

/* --------------------------- */

/*
 * allocate memory for the packet object
 * associate it to the buffer
 */

int packet_create_object(struct packet_object **po, u_char *buf, size_t len)
{

   *po = (struct packet_object *)calloc(1, sizeof(struct packet_object));
   ON_ERROR(*po, NULL, "calloc: cant allocate po");
   
   /* set the buffer and the len of the received packet */
   (*po)->packet = buf;
   (*po)->len = len;
   
   return (0);
}

/*
 * allocate the buffer for displayed data 
 */

int packet_disp_data(struct packet_object *po, u_char *buf, size_t len)
{
   po->disp_data = calloc(len, sizeof(u_char));
   ON_ERROR(po->disp_data, NULL, "calloc: can't allocate disp_data");

   po->disp_len = len;
   memcpy(po->disp_data, buf, len);

   return len;
}

/*
 * free the packet object memory
 */

int packet_destroy_object(struct packet_object **po)
{
   /* free the disp_data pointer */
   SAFE_FREE((*po)->disp_data);
   /* then the po structure */
   SAFE_FREE(*po);

   return 0;

}


int packet_duplicate(struct packet_object *po, char level, u_char **buf)
{

   int len = 0;
   u_char * pobuf = NULL;

   switch (level & LEVEL_MASK ) {
         case LEVEL_2:
            len = po->L2.len;
            pobuf = po->L2.header;
            break;
         case LEVEL_3:
            len = po->L3.len;
            pobuf = po->L3.header;
            break;
         case LEVEL_4:
            len = po->L4.len;
            pobuf = po->L4.header;
            break;
         case LEVEL_DATA:
            len = po->DATA.len;
            pobuf = po->DATA.data;
            break;
         default:
            ERROR_MSG("incorrect level specified");
            break;
   }

   if (level & DUP_ALLOC) {
      *buf = (u_char *)calloc(len, sizeof(u_char));
      if (*buf == NULL)
         ERROR_MSG("calloc()");
   } 

   memcpy(*buf, pobuf, len);

   return len;
}

/* 
 * print a packet object structure...
 * only for debugging purposte
 */

void packet_print(struct packet_object *po)
{
   /* XXX - REMOVE THIS FUNCTION */
   
   char tmp[MAX_ASCII_ADDR_LEN];
   
   USER_MSG("\n=========================================\n");
   USER_MSG("Packet len:  %d\n", po->len);
   USER_MSG("Packet flag: %#x\n", po->flags);
   USER_MSG("L2 : len     %d\n", po->L2.len);
   USER_MSG("     proto   %04X\n", ntohs(po->L2.proto));
   USER_MSG("     src     %s\n", mac_addr_ntoa(po->L2.src, tmp));
   USER_MSG("     dst     %s\n", mac_addr_ntoa(po->L2.dst, tmp));
   USER_MSG("L3 : len     %d\n", po->L3.len);
   USER_MSG("     proto   %04X\n", ntohs(po->L3.proto));
   USER_MSG("     header  %s\n", hex_format(po->L3.header, po->L3.len));
   USER_MSG("     options %s\n", hex_format(po->L3.options, po->L3.optlen));
   USER_MSG("     src     %s\n", ip_addr_ntoa(&po->L3.src, tmp) );
   USER_MSG("     dst     %s\n", ip_addr_ntoa(&po->L3.dst, tmp) );
   USER_MSG("L4 : len     %d\n", po->L4.len);
   USER_MSG("     proto   %02X\n", po->L4.proto);
   USER_MSG("     header  %s\n", hex_format(po->L4.header, po->L4.len));
   USER_MSG("     options %s\n", hex_format(po->L4.options, po->L4.optlen));
   USER_MSG("     src     %d\n", ntohs(po->L4.src) );
   USER_MSG("     dst     %d\n", ntohs(po->L4.dst) );
   USER_MSG("DATA:len     %d\n", po->DATA.len);
   USER_MSG("     data    %s\n", hex_format(po->DATA.data, po->DATA.len));

   
}
   
/* EOF */

// vim:ts=3:expandtab
