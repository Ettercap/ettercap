/*
    etterlog -- create, search and manipulate streams

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

    $Id: el_stream.c,v 1.1 2004/09/13 16:02:31 alor Exp $
*/


#include <el.h>
#include <el_functions.h>

/* protos... */

int stream_create(struct stream_object *so, struct log_header_packet *pck);
int stream_search(struct stream_object *so, char *buf, int versus);
int stream_read(struct stream_object *so, char *buf, size_t size, int mode);
void stream_move(struct stream_object *so, int offset, int whence);
   
/*******************************************/

int stream_create(struct stream_object *so, struct log_header_packet *pck)
{
   return 0;
}

int stream_search(struct stream_object *so, char *buf, int versus)
{
   return 0;
}

int stream_read(struct stream_object *so, char *buf, size_t size, int mode)
{
   return 0;
}

void stream_move(struct stream_object *so, int offset, int whence)
{
}


/* EOF */


// vim:ts=3:expandtab

