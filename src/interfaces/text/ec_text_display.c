/*
    ettercap -- formats and displays the packets

    Copyright (C) ALoR & NaGA

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
#include <ec_packet.h>
#include <ec_interfaces.h>
#include <ec_format.h>

/* proto */

void text_print_packet(struct packet_object *po);
static void display_headers(struct packet_object *po);

/*******************************************/


void text_print_packet(struct packet_object *po)
{
   /* 
    * keep it static so it is always the same
    * memory region used for this operation
    */
   static u_char *tmp = NULL;
   int ret;

   /* don't display the packet */
   if (EC_GBL_OPTIONS->quiet)
      return;
   
   /* 
    * if the regex does not match, the packet is not interesting 
    *
    * should we put this after the format function ?
    * in this way we can match e.t.t.e.r.c.a.p in TEXT mode with
    * the "ettercap" regex
    */
   if (EC_GBL_OPTIONS->regex && 
       regexec(EC_GBL_OPTIONS->regex, (const  char  *)po->DATA.disp_data, 0, NULL, 0) != 0) {
      return;
   }
               
   /* 
    * prepare the buffer,
    * the max length is hex_fomat
    * so use its length for the buffer
    */
   SAFE_REALLOC(tmp, hex_len(po->DATA.disp_len) * sizeof(u_char));

   /* 
    * format the packet with the function set by the user
    */
   ret = EC_GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, tmp);

   /* print the headers */
   display_headers(po);
   
   /* sync stream/descriptor output and print the packet */
   fflush(stdout);
   write(fileno(stdout), tmp, ret);
}     


static void display_headers(struct packet_object *po)
{

   char tmp1[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   char flags[10];
   char *p = flags;
   char proto[5];
   
   memset(flags, 0, sizeof(flags));
   memset(proto, 0, sizeof(proto));   

   /* display the date. ec_ctime() has no newline at end. */
#if defined OS_DARWIN
   fprintf(stdout, "\n\n%s [%d]\n", ec_ctime(&po->ts), po->ts.tv_usec);
#else
   fprintf(stdout, "\n\n%s [%lu]\n", ec_ctime(&po->ts), po->ts.tv_usec);
#endif

   if (EC_GBL_OPTIONS->ext_headers) {
      /* display the mac addresses */
      mac_addr_ntoa(po->L2.src, tmp1);
      mac_addr_ntoa(po->L2.dst, tmp2);
      fprintf(stdout, "%17s --> %17s\n", tmp1, tmp2 );
   }
  
   /* calculate the flags */
   if (po->L4.flags & TH_SYN) *p++ = 'S';
   if (po->L4.flags & TH_FIN) *p++ = 'F';
   if (po->L4.flags & TH_RST) *p++ = 'R';
   if (po->L4.flags & TH_ACK) *p++ = 'A';
   if (po->L4.flags & TH_PSH) *p++ = 'P';
   if (po->L4.flags & TH_URG) *p++ = 'U';
   if (po->L4.flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
   if (po->L4.flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
   *p++ = '\0';
  
   /* determine the proto */
   switch(po->L4.proto) {
      case NL_TYPE_TCP:
         strncpy(proto, "TCP", 4);
         break;
      case NL_TYPE_UDP:
         strncpy(proto, "UDP", 4);
         break;
   }
   
   /* display the ip addresses */
   ip_addr_ntoa(&po->L3.src, tmp1);
   ip_addr_ntoa(&po->L3.dst, tmp2);
   fprintf(stdout, "%s  %s:%d --> %s:%d | %s (%zu)\n", proto, tmp1, ntohs(po->L4.src),
                                                        tmp2, ntohs(po->L4.dst),
                                                        flags, po->DATA.disp_len);
}


/* EOF */

// vim:ts=3:expandtab

