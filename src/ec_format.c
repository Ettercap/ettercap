/*
    ettercap -- formatting functions

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_format.c,v 1.1 2003/03/24 15:56:12 alor Exp $

*/

#include <ec.h>
#include <ec_format.h>

#include <ctype.h>

/* globals */


/* protos */

int hex_format(const u_char *buf, int len, u_char *dst);
int hex_len(int len);


/**********************************/

/* 
 * return the len of the resulting buffer (approximately) 
 */
int hex_len(int len)
{
   int i, nline;
   
   /* calculate the number of lines */
   nline = len / HEX_CHAR_PER_LINE;       
   if (len % HEX_CHAR_PER_LINE) nline++;
   
   /* one line is printed as 66 chars */
   i = nline * 66;

   return i;
}

/* 
 * convert a buffer to a hex form
 */

int hex_format(const u_char *buf, int len, u_char *dst)
{
   int i, j, jm;
   int c, dim = 0;

   memset(dst, 0, hex_len(len));
   
   /* some sanity checks */
   if (len == 0 || buf == NULL) {
      strcpy(dst, "");
      return 0;
   }

   for (i = 0; i < len; i += HEX_CHAR_PER_LINE) {
           sprintf(dst, "%s %04x: ", dst, i );
           jm = len - i;
           jm = jm > HEX_CHAR_PER_LINE ? HEX_CHAR_PER_LINE : jm;

           for (j = 0; j < jm; j++) {
                   if ((j % 2) == 1) 
                      sprintf(dst, "%s%02x ", dst, (u_char) buf[i+j]);
                   else 
                      sprintf(dst, "%s%02x", dst, (u_char) buf[i+j]);
           }
           for (; j < HEX_CHAR_PER_LINE; j++) {
                   if ((j % 2) == 1)
                      strcat(dst, "   ");
                   else
                      strcat(dst, "  ");
           }
           strcat(dst, " ");

           for (j = 0; j < jm; j++) {
                   c = (u_char) buf[i+j];
                   c = isprint(c) ? c : '.';
                   dim = sprintf(dst, "%s%c", dst, c);
           }
           strcat(dst,"\n");
   }

   return dim + 1;
}


/* EOF */

// vim:ts=3:expandtab

