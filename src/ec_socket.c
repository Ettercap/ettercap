/*
    ettercap -- socket handling module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_socket.c,v 1.1 2003/07/11 16:50:24 alor Exp $
*/

#include <ec.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* protos */

int open_socket(char *host, u_int16 port);
int close_socket(int s);
int socket_send(int s, u_char *payload, size_t size);
int socket_recv(int s, u_char *payload, size_t size);

/*******************************************/

/*
 * open a socket to the specified host and port
 */
int open_socket(char *host, u_int16 port)
{
   struct hostent *infh;
   struct sockaddr_in sa_in;
   int sh;

   DEBUG_MSG("open_socket -- [%s]:[%d]", host, port);

   /* prepare the structures */
   bzero((char*)&sa_in, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_port = htons(port);

   /* resolve the hostname */
   if ( (infh = gethostbyname(host)) )
      bcopy(infh->h_addr, (char*)&sa_in.sin_addr, infh->h_length);
   else {
      if ( inet_aton(host, (struct in_addr *)&sa_in.sin_addr.s_addr) == 0 )
         FATAL_MSG("Cannot resolve %s", host);
   }

   /* open the socket */
   if ( (sh = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      ERROR_MSG("Cannot create the socket");
   
   /* connect to the server */
   if ( connect(sh, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0)
      ERROR_MSG("Can't connect to %s on port %d", host, port);

   DEBUG_MSG("open_socket: %d", sh);
   
   return sh;
}

/*
 * close the given socket 
 */
int close_socket(int s)
{
   DEBUG_MSG("close_socket: %d", s);

   /* close the socket */
   return close(s);
}


/* 
 * send a buffer thru the socket 
 */
int socket_send(int s, u_char *payload, size_t size)
{
   /* send data to the socket */
   return write(s, payload, size);
}

/*
 * receive data from the socket
 */
int socket_recv(int sh, u_char *payload, size_t size)
{
   /* read up to size byte */
   return read(sh, payload, size);
}


/* EOF */

// vim:ts=3:expandtab

