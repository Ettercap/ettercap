/*
    ettercap -- SSL support

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

    $Id: ec_sslwrap.c,v 1.13 2004/03/11 13:55:13 lordnaga Exp $
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>

// XXX - check if we have poll.h
#include <sys/poll.h>

/* don't include kerberos. RH sux !! */
#define OPENSSL_NO_KRB5 1

#include <openssl/ssl.h>

#include <ec.h>
#include <ec_decode.h>
#include <ec_session.h>
#include <ec_hook.h>
#include <ec_dissect.h>
#include <ec_threads.h>
#include <ec_sslwrap.h>

//XXX - Only to make it compile
#define CERT_FILE "etter.ssl.crt"
#define DATA_PATH "/"

#define BREAK_ON_ERROR(x,y,z) do {\
if (x != ESUCCESS) {\
sslw_wipe_connection(y);\
SAFE_FREE(z.DATA.data);\
SAFE_FREE(z.DATA.disp_data);\
return NULL;\
}} while(0);\


/* globals */

static LIST_HEAD (, listen_entry) listen_ports;

struct listen_entry {
   int fd;
   u_int16 sslw_port;   /* Port where we want to wrap SSL */
   u_int16 redir_port;  /* Port where accepts connections */
   u_char status;       /* Use directly SSL or not */
   LIST_ENTRY (listen_entry) next;
};

struct accepted_entry {
   int32 fd[2];   /* 0->Client, 1->Server */
   u_int16 port[2];
   struct ip_addr ip[2];
   SSL *ssl[2];
   u_char status;
   #define SSL_CLIENT 0
   #define SSL_SERVER 1
};

/* Session identifier 
 * It has to be even-lenghted for session hash matching */
struct sslw_ident {
   u_int32 magic;
      #define SSLW_MAGIC  0x0501e77e
   struct ip_addr L3_src;
   u_int16 L4_src;
   u_int16 L4_dst;
};
#define SSLW_IDENT_LEN sizeof(struct sslw_ident)

#define SSLW_RETRY 5
#define SSLW_WAIT 10000

SSL_CTX   *ssl_ctx_client, *ssl_ctx_server;


/* protos */

void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status);
EC_THREAD_FUNC(sslw_start);
static EC_THREAD_FUNC(sslw_child);
static int sslw_is_ssl(struct packet_object *po);
static int sslw_connect_server(struct accepted_entry *ae);
static int sslw_sync_conn(struct accepted_entry *ae);
static int sslw_get_peer(struct accepted_entry *ae);
static void sslw_bind_wrapper(void);
static int sslw_read_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po);
static int sslw_write_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po);
static void sslw_wipe_connection(struct accepted_entry *ae);
static void sslw_init(void);
static int sslw_match(void *id_sess, void *id_curr);
static void sslw_create_session(struct ec_session **s, struct packet_object *po);
static size_t sslw_create_ident(void **i, struct packet_object *po);            
static void sslw_hook_handled(struct packet_object *po);


/* 
 * Filter SSL related packets and create NAT sessions.
 * It hooks HOOK_HANDLED.
 */
static void sslw_hook_handled(struct packet_object *po)
{
   struct ec_session *s = NULL;

   /* We have nothing to do with this packet */
   if (!sslw_is_ssl(po))
      return;
      
   /* If it's an ssl packet don't parse it and don't forward */
   po->flags |= (PO_DROPPED | PO_IGNORE);
   
   /* If it's a new connection */
   if ( (po->flags & PO_FORWARDABLE) && 
        (po->L4.flags & TH_SYN) &&
        !(po->L4.flags & TH_ACK) ) {
	
      sslw_create_session(&s, PACKET);

      /* Remember the real destination IP */
      memcpy(s->data, &po->L3.dst, sizeof(struct ip_addr));
      session_put(s);
   }
}


/* 
 * Register a new ssl wrapper 
 */
void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status)
{
   struct listen_entry *le;
   
   SAFE_CALLOC(le, 1, sizeof(struct listen_entry));
 
   le->sslw_port = port;
   le->status = status;

   /* Insert it in the port list where listen for connections */ 
   LIST_INSERT_HEAD(&listen_ports, le, next);    

   dissect_add(name, APP_LAYER_TCP, port, decoder); 
}


/* 
 * Check if this packet is for ssl wrappers 
 */
static int sslw_is_ssl(struct packet_object *po)
{
   struct listen_entry *le;
   
   /* If it's already coming from ssl wrapper */ 
   if (po->flags & PO_FROMSSL) 
      return 0;

   LIST_FOREACH(le, &listen_ports, next) {
      if (ntohs(po->L4.dst) == le->sslw_port ||
          ntohs(po->L4.src) == le->sslw_port)
         return 1;
   }
   return 0;
}


/*
 * Bind all registered wrappers to free ports. 
 */ 
static void sslw_bind_wrapper(void)
{
   u_int16 bind_port = 0xe77e; 
   struct listen_entry *le;
   struct sockaddr_in sa_in;

   LIST_FOREACH(le, &listen_ports, next) { 
   
      le->fd = socket(AF_INET, SOCK_STREAM, 0);
      fcntl(le->fd, F_SETFL, O_NONBLOCK);

      memset(&sa_in, 0, sizeof(sa_in));
      sa_in.sin_family = AF_INET;
      sa_in.sin_addr.s_addr = INADDR_ANY;
   
      do {
         bind_port++;
         sa_in.sin_port = htons(bind_port);
         le->redir_port = bind_port;
      } while ( bind(le->fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0);

      DEBUG_MSG("sslw - bind %d on %d", le->sslw_port, le->redir_port);
      listen(le->fd, 100);      
   }
}


static int sslw_sync_conn(struct accepted_entry *ae)
{      
   if(sslw_get_peer(ae) != ESUCCESS)
         return -EINVALID;
	 
   if(sslw_connect_server(ae) != ESUCCESS)
         return -EINVALID;
	 
   return ESUCCESS;
}
   
static int sslw_sync_ssl(struct accepted_entry *ae) {
   
   ae->ssl[SSL_SERVER] = SSL_new(ssl_ctx_server);
   SSL_set_connect_state(ae->ssl[SSL_SERVER]);
   SSL_set_fd(ae->ssl[SSL_SERVER], ae->fd[SSL_SERVER]);
   ae->ssl[SSL_CLIENT] = SSL_new(ssl_ctx_client);
   SSL_set_fd(ae->ssl[SSL_CLIENT], ae->fd[SSL_CLIENT]);
 
   if (SSL_connect(ae->ssl[SSL_SERVER]) != 1) {
      SSL_free(ae->ssl[SSL_SERVER]);
      SSL_free(ae->ssl[SSL_CLIENT]);
      return -EINVALID;
   }

   if (SSL_accept(ae->ssl[SSL_CLIENT]) != 1) {
      SSL_free(ae->ssl[SSL_SERVER]);
      SSL_free(ae->ssl[SSL_CLIENT]);
      return -EINVALID;
   }

   return ESUCCESS;
}


static int sslw_get_peer(struct accepted_entry *ae)
{
   struct ec_session *s = NULL;
   struct packet_object po;
   void *ident = NULL;
   int i;
 
   /* Take the server IP address from the NAT sessions */
   memcpy(&po.L3.src, &ae->ip[SSL_CLIENT], sizeof(struct ip_addr));
   po.L4.src = ae->port[SSL_CLIENT];
   po.L4.dst = ae->port[SSL_SERVER];
   
   sslw_create_ident(&ident, &po);
   
   /* 
    * A little waiting loop because the sniffing thread , 
    * which creates the session, may be slower than this
    */
   for (i=0; i<SSLW_RETRY && session_get_and_del(&s, ident, SSLW_IDENT_LEN)!=ESUCCESS; i++)
      usleep(SSLW_WAIT);

   if (i==SSLW_RETRY) {
      SAFE_FREE(ident);
      return -EINVALID;
   }
   
   /* Remember the server IP address in the sessions */
   memcpy(&ae->ip[SSL_SERVER], s->data, sizeof(struct ip_addr));
   
   SAFE_FREE(s->data);
   SAFE_FREE(s);
   SAFE_FREE(ident);

   return ESUCCESS;
}


/* 
 * Take the other peer (server) from ssl-decoders' sessions
 * and contact it. 
 * Check if we have to enter SSL state.
 */
static int sslw_connect_server(struct accepted_entry *ae)
{
   struct sockaddr_in sin;
   
   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_port = ae->port[SSL_SERVER];
   sin.sin_addr.s_addr = ip_addr_to_int32(ae->ip[SSL_SERVER].addr);
 
   /* Standard connection to the server */
   if ( (ae->fd[SSL_SERVER] = socket(AF_INET, SOCK_STREAM, 0)) == -1)
      return -EINVALID;

   if (connect(ae->fd[SSL_SERVER], (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
      close(ae->fd[SSL_SERVER]);
      return -EINVALID;   
   }      
	       
   return ESUCCESS;   
}


/* 
 * Read the data from an accepted connection. 
 * Check if it already entered SSL state.
 */ 
static int sslw_read_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   int len;
   
   if (ae->status & SSL_ENABLED)
      len = SSL_read(ae->ssl[direction], po->DATA.data, GBL_IFACE->mtu);
   else       
      len = read(ae->fd[direction], po->DATA.data, GBL_IFACE->mtu);

   if (len <= 0) 
      return -EINVALID;
   
   po->len = len;
   po->DATA.len = len;
   /* NULL terminate the data buffer */
   po->DATA.data[po->DATA.len] = 0;
 
   /* create the buffer to be displayed */
   packet_destroy_object(po);
   packet_disp_data(po, po->DATA.data, po->DATA.len);
  
   return ESUCCESS;
}


/* 
 * Write the data into an accepted connection. 
 * Check if it already entered SSL state.
 */ 
static int sslw_write_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   int len;
      
   /* Write packet data */
   if (ae->status & SSL_ENABLED)
      len = SSL_write(ae->ssl[direction], po->DATA.data, po->DATA.len + po->DATA.inject_len);
   else       
      len = write(ae->fd[direction], po->DATA.data, po->DATA.len + po->DATA.inject_len);

   if (len <= 0)
      return -ENOTHANDLED; 
      
   return ESUCCESS;
}


/* 
 * Fill the packet object and put it in 
 * the dissector stack (above protocols decoders)
 */
static void sslw_parse_packet(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   FUNC_DECODER_PTR(start_decoder);
   int len;

   memcpy(&po->L3.src, &ae->ip[direction], sizeof(struct ip_addr));
   memcpy(&po->L3.dst, &ae->ip[!direction], sizeof(struct ip_addr));
   
   po->L4.src = ae->port[direction];
   po->L4.dst = ae->port[!direction];
   
   po->flags |= PO_FROMSSL;
   
   po->DATA.inject = NULL;
   po->DATA.inject_len = 0;
   
   /* get current time */
   gettimeofday(&po->ts, NULL);

   /* calculate if the dest is local or not */
   switch (ip_addr_is_local(&PACKET->L3.src)) {
      case ESUCCESS:
         PACKET->PASSIVE.flags &= ~FP_HOST_NONLOCAL;
         PACKET->PASSIVE.flags |= FP_HOST_LOCAL;
         break;
      case -ENOTFOUND:
         PACKET->PASSIVE.flags &= ~FP_HOST_LOCAL;
         PACKET->PASSIVE.flags |= FP_HOST_NONLOCAL;
         break;
      case -EINVALID:
         PACKET->PASSIVE.flags = FP_UNKNOWN;
         break;
   }

   /* Let's start from the last stage of decoder chain */
   start_decoder =  get_decoder(APP_LAYER, PL_DEFAULT);
   start_decoder(po->DATA.data, po->DATA.len, &len, po);
}


/* 
 * Remove the connection from the accepted 
 * list and close both sockets.
 */
static void sslw_wipe_connection(struct accepted_entry *ae)
{
// XXX - SSL_free chiude anche gli fd?
   if (ae->ssl[SSL_CLIENT]) {
      /* They are initialized together */
      SSL_free(ae->ssl[SSL_CLIENT]);
      SSL_free(ae->ssl[SSL_SERVER]);
   } else {
      close(ae->fd[SSL_CLIENT]);
      close(ae->fd[SSL_SERVER]);
   }

   SAFE_FREE(ae);
}


/* 
 * Initialize SSL stuff 
 */
static void sslw_init(void)
{
   SSL_library_init();

   ssl_ctx_client = SSL_CTX_new(SSLv23_server_method());
   ssl_ctx_server = SSL_CTX_new(SSLv23_client_method());

   if (SSL_CTX_use_certificate_file(ssl_ctx_client, CERT_FILE, SSL_FILETYPE_PEM) == 0) {
      if (SSL_CTX_use_certificate_file(ssl_ctx_client, DATA_PATH "/" CERT_FILE, SSL_FILETYPE_PEM) == 0)
         FATAL_ERROR("Can't open \"%s\" file !!", CERT_FILE);
   }

   if (SSL_CTX_use_PrivateKey_file(ssl_ctx_client, CERT_FILE, SSL_FILETYPE_PEM) == 0) {
      DEBUG_MSG("sslw -- SSL_CTX_use_PrivateKey_file -- %s", DATA_PATH "/" CERT_FILE);

      if (SSL_CTX_use_PrivateKey_file(ssl_ctx_client, DATA_PATH "/" CERT_FILE, SSL_FILETYPE_PEM) == 0)
         FATAL_ERROR("Can't open \"%s\" file !!", CERT_FILE);
   }

   if (SSL_CTX_check_private_key(ssl_ctx_client) == 0)
      FATAL_ERROR("Bad SSL Key couple !!");
}

EC_THREAD_FUNC(sslw_child)
{
   struct pollfd poll_fd[2];
   struct packet_object po;
   int direction, ret_val;
   struct accepted_entry *ae;

   ae = (struct accepted_entry *)args;
   ec_thread_init();
 
   /* Contact the real server */
   if (sslw_sync_conn(ae) == -EINVALID) {
      close(ae->fd[SSL_CLIENT]);
      SAFE_FREE(ae);
      return NULL;
   }	    
	    
   if ((ae->status & SSL_ENABLED) && 
       sslw_sync_ssl(ae) == -EINVALID) {
      SAFE_FREE(ae);
      return NULL;
   }

   /* 
    * Allocate the data buffer and initialize 
    * fake headers. Headers len is set to 0.
    * XXX - Be sure to not modify these len.
    */
   memset(&po, 0, sizeof(struct packet_object));
   SAFE_CALLOC(po.DATA.data, 1, UINT16_MAX);
   po.L2.header  = po.DATA.data; 
   po.L3.header  = po.DATA.data;
   po.L3.options = po.DATA.data;
   po.L4.header  = po.DATA.data;
   po.L4.options = po.DATA.data;
   po.fwd_packet = po.DATA.data;
   po.packet     = po.DATA.data;
   
   po.L3.proto = htons(LL_TYPE_IP);
   po.L3.ttl = 64;
   po.L4.proto = NL_TYPE_TCP;

   /* A fake SYN ACK for profiles */
   /* XXX - Does anyone care about packet len after this point? */
   po.len = 64;
   po.L4.flags = (TH_SYN | TH_ACK);
   packet_disp_data(&po, po.DATA.data, po.DATA.len);
   sslw_parse_packet(ae, SSL_SERVER, &po);
   po.L4.flags = 0;
   
   LOOP {
      // XXX Posso metterlo fuori dal ciclo?
      poll_fd[SSL_CLIENT].fd = ae->fd[SSL_CLIENT];
      poll_fd[SSL_CLIENT].events = POLLIN;
      poll_fd[SSL_SERVER].fd = ae->fd[SSL_SERVER];
      poll_fd[SSL_SERVER].events = POLLIN;

      if (poll(poll_fd, 2, GBL_CONF->connection_timeout*1000) == 0)
         BREAK_ON_ERROR(-EINVALID,ae,po);

      for(direction=0; direction<2; direction++) 
         if (poll_fd[direction].revents & POLLIN) {
            ret_val = sslw_read_data(ae, direction, &po);
            BREAK_ON_ERROR(ret_val,ae,po);
	    
            sslw_parse_packet(ae, direction, &po);
            if (po.flags & PO_DROPPED)
               continue;

            ret_val = sslw_write_data(ae, !direction, &po);
            BREAK_ON_ERROR(ret_val,ae,po);
         } else if (poll_fd[direction].revents & (POLLHUP | POLLERR | POLLNVAL))
            BREAK_ON_ERROR(-EINVALID,ae,po);
   }
}



/* 
 * SSL thread main function.
 */
EC_THREAD_FUNC(sslw_start)
{
   struct pollfd *poll_fd = NULL;
   struct listen_entry *le;
   struct accepted_entry *ae;
   u_int16 number_of_services;
   u_int32 len = sizeof(struct sockaddr_in), i;
   struct sockaddr_in client_sin;
   
   ec_thread_init();
   
   sslw_init();
   sslw_bind_wrapper();
   hook_add(HOOK_HANDLED, &sslw_hook_handled);

   number_of_services = 0;
   LIST_FOREACH(le, &listen_ports, next) 
      number_of_services++;
   
   SAFE_CALLOC(poll_fd, 1, sizeof(struct pollfd) * number_of_services);

   LOOP {
      /* Set the polling on all registered ssl services */
      // XXX - Posso metterlo fuori dal ciclo???
      i=0;
      LIST_FOREACH(le, &listen_ports, next) {
         poll_fd[i].fd = le->fd;
         poll_fd[i++].events = POLLIN;
      }

      poll(poll_fd, number_of_services, -1);
      
      /* Check which port received connection */
      for(i=0; i<number_of_services; i++) 
         if (poll_fd[i].revents & POLLIN) {
	 
            LIST_FOREACH(le, &listen_ports, next) 
               if (poll_fd[i].fd == le->fd)
                  break;
	    
            DEBUG_MSG("ssl_wrapper -- got a connection on port %d [%d]", le->redir_port, le->sslw_port);
            SAFE_CALLOC(ae, 1, sizeof(struct accepted_entry));
	    
            ae->fd[SSL_CLIENT] = accept(poll_fd[i].fd, (struct sockaddr *)&client_sin, &len);
            
            /* Error checking */
            if (ae->fd[SSL_CLIENT] == -1) {
               SAFE_FREE(ae);
               continue;
            }
	    
            /* Set the server original port for protocol dissection */
            ae->port[SSL_SERVER] = htons(le->sslw_port);
            
            /* Check if we have to enter SSL status */
            ae->status = le->status;
	       
            /* Set the peer (client) in the connection list entry */
            ae->port[SSL_CLIENT] = client_sin.sin_port;
            ip_addr_init(&(ae->ip[SSL_CLIENT]), AF_INET, (char *)&(client_sin.sin_addr.s_addr));
	    
            ec_thread_new("sslw_child", "ssl child", &sslw_child, ae);
         }
   }
}	 


/*******************************************/
/* Sessions' stuff for ssl packets */

static size_t sslw_create_ident(void **i, struct packet_object *po)
{
   struct sslw_ident *ident;

   /* allocate the ident for that session */
   SAFE_CALLOC(ident, 1, sizeof(struct sslw_ident));

   /* the magic */
   ident->magic = SSLW_MAGIC;
      
   /* prepare the ident */
   memcpy(&ident->L3_src, &po->L3.src, sizeof(struct ip_addr));

   ident->L4_src = po->L4.src;
   ident->L4_dst = po->L4.dst;

   /* return the ident */
   *i = ident;

   /* return the lenght of the ident */
   return sizeof(struct sslw_ident);
}


static int sslw_match(void *id_sess, void *id_curr)
{
   struct sslw_ident *ids = id_sess;
   struct sslw_ident *id = id_curr;

   /* sanity check */
   BUG_IF(ids == NULL);
   BUG_IF(id == NULL);
  
   /* 
    * is this ident from our level ?
    * check the magic !
    */
   if (ids->magic != id->magic)
      return 0;

   if (ids->L4_src == id->L4_src &&
       ids->L4_dst == id->L4_dst &&
       !ip_addr_cmp(&ids->L3_src, &id->L3_src)) 
      return 1;
   
   return 0;
}


static void sslw_create_session(struct ec_session **s, struct packet_object *po)
{
   void *ident;

   DEBUG_MSG("sslw_create_session");

   /* allocate the session */
   SAFE_CALLOC(*s, 1, sizeof(struct ec_session));
   
   /* create the ident */
   (*s)->ident_len = sslw_create_ident(&ident, po);
   
   /* link to the session */
   (*s)->ident = ident;

   /* the matching function */
   (*s)->match = &sslw_match;

   /* alloc of data elements */
   SAFE_CALLOC((*s)->data, 1, sizeof(struct ip_addr));
}

/* EOF */

// vim:ts=3:expandtab

