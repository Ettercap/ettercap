/*
    etterlog -- extractor for http and proxy -- TCP 80, 8080

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

    $Id: el_decode_http.c,v 1.2 2004/10/11 14:55:49 alor Exp $
*/

#include <el.h>
#include <el_functions.h>

/* globals */

/* protos */
FUNC_EXTRACTOR(extractor_http);
void http_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init http_init(void)
{
   add_extractor(APP_LAYER_TCP, 80, extractor_http);
   add_extractor(APP_LAYER_TCP, 8080, extractor_http);
}


FUNC_EXTRACTOR(extractor_http)
{
   char buf[10240];

   memset(buf, 0, sizeof(buf));

   stream_read(STREAM, buf, 10, STREAM_BOTH);

   printf("\n");
   
   printf("buf: %s\n", buf);

   memset(buf, 0, sizeof(buf));
   
   stream_search(STREAM, "\r\n\r\n", STREAM_BOTH);

   //stream_move(STREAM, 0, SEEK_SET, STREAM_BOTH);
   
   stream_read(STREAM, buf, 29, STREAM_BOTH);

   printf("buf: %s\n", buf);
   
   return STREAM_DECODED;
}


/* EOF */

// vim:ts=3:expandtab
