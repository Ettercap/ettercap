/*
    ettercap -- diplay the connection list 

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

    $Id: ec_text_conn.c,v 1.2 2003/11/14 20:17:46 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_interfaces.h>
#include <ec_conntrack.h>
#include <ec_inet.h>
#include <ec_proto.h>

/* globals */

/* proto */

void text_connections(void);
void conn_print(int n, struct conn_object *co);

/*******************************************/

void text_connections(void)
{   
   fprintf(stdout, "\nConnections list:\n\n");
  
   /* call the callbacking function */
   conntrack_print(1, INT_MAX, &conn_print); 

   fprintf(stdout, "\n");
}

/*
 * prints a connection
 */
void conn_print(int n, struct conn_object *co)
{
   char tmp[MAX_ASCII_ADDR_LEN];

   fprintf(stdout, "%3d)  ", n);
   switch (co->L4_proto) {
      case NL_TYPE_UDP:
         fprintf(stdout, "U ");
         break;
      case NL_TYPE_TCP:
         fprintf(stdout, "T ");
         break;
      default:
         fprintf(stdout, "  ");
         break;
   }
   fprintf(stdout, "%15s:%-5d -- ", ip_addr_ntoa(&co->L3_addr1, tmp), ntohs(co->L4_addr1));   
   fprintf(stdout, "%15s:%-5d ", ip_addr_ntoa(&co->L3_addr2, tmp), ntohs(co->L4_addr2));   
   switch (co->status) {
      case CONN_IDLE:
         fprintf(stdout, "IDLE    ");
         break;
      case CONN_OPENING:
         fprintf(stdout, "OPENING ");
         break;
      case CONN_OPEN:
         fprintf(stdout, "OPEN    ");
         break;
      case CONN_ACTIVE:
         fprintf(stdout, "ACTIVE  ");
         break;
      case CONN_CLOSING:
         fprintf(stdout, "CLOSING ");
         break;
      case CONN_CLOSED:
         fprintf(stdout, "CLOSED  ");
         break;
      case CONN_KILLED:
         fprintf(stdout, "KILLED  ");
         break;
   }
   fprintf(stdout, "  TX: %d", co->xferred);

   if (co->DISSECTOR.user) {
      fprintf(stdout, "\n\t\tUSER: %s", co->DISSECTOR.user);
      fprintf(stdout, "\n\t\tPASS: %s", co->DISSECTOR.pass);
      if (co->DISSECTOR.info)
         fprintf(stdout, "\n\t\tINFO: %s", co->DISSECTOR.info);
   }
   
   fprintf(stdout, "\n");

}


/* EOF */

// vim:ts=3:expandtab

