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

    $Id: ec_sslwrap.c,v 1.8 2004/03/10 11:14:05 lordnaga Exp $
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


#define BREAK_ON_ERROR(x,y) if (x == -EINVALID) { \
      sslw_wipe_connection(y); \
      break; \
   } \
   if (x != ESUCCESS) \
      continue; \


/* globals */

static LIST_HEAD (, listen_entry) listen_ports;
static LIST_HEAD (, accepted_entry) accepted_conn;

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
   u_int16 poll_stat[2];
   u_char status;
   LIST_ENTRY (accepted_entry) next;
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
   int ret_val, err;
   
   //DEBUG_MSG("sslw - XXX Start SYNC");
   if (! (ae->status & SSL_PEER_DONE) ) {
      if (sslw_get_peer(ae) != ESUCCESS)
         return -EINVALID;
      ae->status |= SSL_PEER_DONE;
   }
   
   if(! (ae->status & SSL_CONN_DONE) ) {
      switch (sslw_connect_server(ae)) {
         case -EINVALID:
	    return -EINVALID;
            break;
         case -ENOTHANDLED:
	    ae->poll_stat[SSL_CLIENT] = 0;
	    ae->poll_stat[SSL_SERVER] = POLLOUT;
	    DEBUG_MSG("SYNC CONN");
	    return -ENOTHANDLED;
	    break;
	 default:
	    ae->status |= SSL_CONN_DONE;
	    ae->poll_stat[SSL_CLIENT] = POLLIN;
	    ae->poll_stat[SSL_SERVER] = POLLIN;
	    break;
      }     
   }
   
   if ( ae->status & SSL_ENABLED ) {
   
      if (! (ae->status & SSL_CTX_DONE) ) {
         ae->ssl[SSL_SERVER] = SSL_new(ssl_ctx_server);
         SSL_set_connect_state(ae->ssl[SSL_SERVER]);
         SSL_set_fd(ae->ssl[SSL_SERVER], ae->fd[SSL_SERVER]);
         ae->ssl[SSL_CLIENT] = SSL_new(ssl_ctx_client);
         SSL_set_fd(ae->ssl[SSL_CLIENT], ae->fd[SSL_CLIENT]);
	 ae->status |= SSL_CTX_DONE;
      }         

      if (! (ae->status & SSL_SERV_DONE) ) {
         ret_val = SSL_connect(ae->ssl[SSL_SERVER]); 
         switch (ret_val) {
            case 1: 
	       ae->status |= SSL_SERV_DONE;
	       break;
	    case 0: 
	       // Do we have to close standard descriptors?
	       // If so add here the server close
	       // If not delete the client close in the main loop
	       SSL_free(ae->ssl[SSL_SERVER]);
	       SSL_free(ae->ssl[SSL_CLIENT]);
	       return -EINVALID;
	       break;
	    default:
	       ae->poll_stat[SSL_CLIENT] = 0;
	       err = SSL_get_error(ae->ssl[SSL_SERVER], ret_val);
	       if ( err == SSL_ERROR_WANT_READ)
	          ae->poll_stat[SSL_SERVER] = POLLIN;
	       else if ( err == SSL_ERROR_WANT_WRITE)
	          ae->poll_stat[SSL_SERVER] = POLLOUT;
	       else 
	          return -EINVALID;
	
	DEBUG_MSG("SYNC SERV");	  
	       return -ENOTHANDLED;
	       break;
         }
      }      

      if (! (ae->status & SSL_CLNT_DONE) ) {
         ret_val = SSL_accept(ae->ssl[SSL_CLIENT]); 
         switch (ret_val) {
            case 1: 
	       ae->status |= SSL_CLNT_DONE;
	       ae->poll_stat[SSL_SERVER] = POLLIN;
	       ae->poll_stat[SSL_CLIENT] = POLLIN;
	       break;
	    case 0: 
	       // Do we have to close standard descriptors?
	       // If so add here the server close
	       // If not delete the client close in the main loop
	       SSL_free(ae->ssl[SSL_SERVER]);
	       SSL_free(ae->ssl[SSL_CLIENT]);
	       return -EINVALID;
	       break;
	    default:
	       ae->poll_stat[SSL_SERVER] = 0;
	       err = SSL_get_error(ae->ssl[SSL_CLIENT], ret_val);
	       if (err == SSL_ERROR_WANT_READ)
	          ae->poll_stat[SSL_CLIENT] = POLLIN;
	       else if (err == SSL_ERROR_WANT_WRITE)     
	          ae->poll_stat[SSL_CLIENT] = POLLOUT;
	       else
	          return -EINVALID;
	DEBUG_MSG("SYNC CLIENT %d", (u_int32)ae);	  
	       return -ENOTHANDLED;
	       break;
         }
      }               
   }
   //DEBUG_MSG("sslw - XXX End SYNC");
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
      if (errno == EINPROGRESS)
         return -ENOTHANDLED;
	
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
   int len, err;
   
   DEBUG_MSG("xx to read xxx");
   if (ae->status & SSL_ENABLED)
      len = SSL_read(ae->ssl[direction], po->DATA.data, GBL_IFACE->mtu);
   else       
      len = read(ae->fd[direction], po->DATA.data, GBL_IFACE->mtu);

   DEBUG_MSG("xx letti %d xx", len);
   if (len < 0) {
      if (!(ae->status & SSL_ENABLED) && errno == EAGAIN)
         return -ENOTHANDLED; 
      
      if (ae->status & SSL_ENABLED) {
         err = SSL_get_error(ae->ssl[direction], len);
	 if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
	    return -ENOTHANDLED;     
      } 
      return -EINVALID;
   }   

   if (ae->status & SSL_ENABLED && len == 0) {
      DEBUG_MSG("XXX INVALIDO");
      return -EINVALID;
   }
   
   po->DATA.len = len;
   /* NULL terminate the data buffer */
   po->DATA.data[po->DATA.len] = 0;
 
    /* create the buffer to be displayed */
   packet_disp_data(po, po->DATA.data, po->DATA.len);
  
   return ESUCCESS;
}


/* 
 * Write the data into an accepted connection. 
 * Check if it already entered SSL state.
 */ 
static int sslw_write_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   int len, err;
   
   DEBUG_MSG("sslw - WRITING DATA %d", (u_int32)ae);
   
   /* Write packet data */
   if (ae->status & SSL_ENABLED)
      len = SSL_write(ae->ssl[direction], po->DATA.data, po->DATA.len + po->DATA.inject_len);
   else       
      len = write(ae->fd[direction], po->DATA.data, po->DATA.len + po->DATA.inject_len);
   DEBUG_MSG("sslw - WRITING DATA LEN %d %d",po->DATA.len + po->DATA.inject_len, len);
if (po->DATA.len + po->DATA.inject_len != (u_int32)len)
 DEBUG_MSG("MANNAGGIA LA PUTTANA DI EVA'''''''''''''''''''''''''''''''''''");


   if (len < 0) {
      if (! (ae->status & SSL_ENABLED) && errno == EAGAIN)
         return -ENOTHANDLED; 
      
      if (ae->status & SSL_ENABLED) {
         err = SSL_get_error(ae->ssl[direction], len);
	 if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
	    return -ENOTHANDLED;     
      } 
      return -EINVALID;
   }   


   // XXX Lo lascio???????????????????????/
   if (ae->status & SSL_ENABLED && len == 0) {
      DEBUG_MSG("XXX INVALIDO WRITE");
      return -EINVALID;
   }

   //DEBUG_MSG("sslw - END WRITING");      
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
//DEBUG_MSG("XXX -- wipe");
   LIST_REMOVE(ae, next);
   if (ae->ssl[SSL_CLIENT]) {
      /* They are initialized together */
      SSL_free(ae->ssl[SSL_CLIENT]);
      SSL_free(ae->ssl[SSL_SERVER]);
   } else {
      close(ae->fd[SSL_CLIENT]);
      close(ae->fd[SSL_SERVER]);
   }
//DEBUG_MSG("XXX -- End wipe");

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
      DEBUG_MSG("Grell_init -- SSL_CTX_use_PrivateKey_file -- %s", DATA_PATH "/" CERT_FILE);

      if (SSL_CTX_use_PrivateKey_file(ssl_ctx_client, DATA_PATH "/" CERT_FILE, SSL_FILETYPE_PEM) == 0)
         FATAL_ERROR("Can't open \"%s\" file !!", CERT_FILE);
   }

   if (SSL_CTX_check_private_key(ssl_ctx_client) == 0)
      FATAL_ERROR("Bad SSL Key couple !!");
}


/* 
 * SSL thread main function.
 */
EC_THREAD_FUNC(sslw_start)
{
   struct pollfd *poll_fd = NULL;
   struct listen_entry *le;
   struct accepted_entry *ae;
   u_int16 number_of_services, number_of_connections, i, j;
   u_int32 len = sizeof(struct sockaddr_in);
   int ret_val;
   struct sockaddr_in client_sin;
   struct packet_object po;
   
   ec_thread_init();
   
   sslw_init();
   sslw_bind_wrapper();
   hook_add(HOOK_HANDLED, &sslw_hook_handled);

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

   LOOP {
      /* See how many services and connections we have */
      number_of_services = 0;
      LIST_FOREACH(le, &listen_ports, next) 
         number_of_services++;

      number_of_connections = 0;
      LIST_FOREACH(ae, &accepted_conn, next) 
         number_of_connections++;

      SAFE_REALLOC(poll_fd, sizeof(struct pollfd) * (number_of_connections*2 + number_of_services));

      i = 0;
      /* Set the polling on all registered ssl services */
      LIST_FOREACH(le, &listen_ports, next) {
         poll_fd[i].fd = le->fd;
         poll_fd[i++].events = POLLIN;
      }
         
      /* Set the polling on all connections (after the services) */
      LIST_FOREACH(ae, &accepted_conn, next) {
         poll_fd[i].fd = ae->fd[SSL_CLIENT];
         poll_fd[i++].events = ae->poll_stat[SSL_CLIENT];
         poll_fd[i].fd = ae->fd[SSL_SERVER];
         poll_fd[i++].events = ae->poll_stat[SSL_SERVER];
      }

      CANCELLATION_POINT();
      // XXX - CONTROLLARE ERRORI POSSIBILI DELLA POLL
      DEBUG_MSG("---------------- NUOVA POLL --------------------");
      poll(poll_fd, number_of_connections*2 + number_of_services, -1);
      CANCELLATION_POINT();
      
      /* Check which port received connection */
      for(i=0; i<number_of_services; i++) 
         if (poll_fd[i].revents & POLLIN) {
	 
            j = 0;
            LIST_FOREACH(le, &listen_ports, next) {
               if (j==i)
                  break;
               j++;   
            }        
	    
            DEBUG_MSG("ssl_wrapper -- got a connection on port %d [%d]", le->redir_port, le->sslw_port);
            SAFE_CALLOC(ae, 1, sizeof(struct accepted_entry));
	    
            ae->fd[SSL_CLIENT] = accept(poll_fd[i].fd, (struct sockaddr *)&client_sin, &len);
            
            /* Error checking */
            if (ae->fd[SSL_CLIENT] == -1) {
               SAFE_FREE(ae);
               continue;
            }
            fcntl(ae->fd[SSL_CLIENT], F_SETFL, O_NONBLOCK);
	    
            /* Set the server original port for protocol dissection */
            ae->port[SSL_SERVER] = htons(le->sslw_port);
            
            /* Check if we have to enter SSL status */
            ae->status = le->status;
	       
            /* Set the peer (client) in the connection list entry */
            ae->port[SSL_CLIENT] = client_sin.sin_port;
            ip_addr_init(&(ae->ip[SSL_CLIENT]), AF_INET, (char *)&(client_sin.sin_addr.s_addr));

            /* Contact the real server */
            if (sslw_sync_conn(ae) == -EINVALID) {
               close(ae->fd[SSL_CLIENT]);
               SAFE_FREE(ae);
               continue;
            }
	    
            LIST_INSERT_HEAD(&accepted_conn, ae, next);   
         }
	 

      /* Check if we have data to read */
      for(i=0; i<number_of_connections*2; i++) 
         if (poll_fd[i+number_of_services].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR | POLLNVAL)) {
            u_int32 direction;//, connection;

DEBUG_MSG("-- conn accpted --");	    
            /* Check if it's server or client and which connection */
            direction = i%2;
            LIST_FOREACH(ae, &accepted_conn, next) {
	       if (poll_fd[i+number_of_services].fd == ae->fd[SSL_CLIENT] ||
	           poll_fd[i+number_of_services].fd == ae->fd[SSL_SERVER]);
	          break;
            }
	    /* Error checking */
	    if (!ae)
	       break; 
DEBUG_MSG("-- conn found --");	    

	    if (poll_fd[i+number_of_services].revents & (POLLHUP | POLLERR | POLLNVAL)) {
               /* if HUP remove the entry from the list */
               sslw_wipe_connection(ae);
	       break;
	    }
DEBUG_MSG("-- conn action --");	    

            ret_val = sslw_sync_conn(ae);
	    BREAK_ON_ERROR(ret_val, ae);
DEBUG_MSG("-- conn read --");	    
            
	    ret_val = sslw_read_data(ae, direction, &po);
	    BREAK_ON_ERROR(ret_val, ae);

DEBUG_MSG("-- conn parse --");	    

//DEBUG_MSG("YYYYYYYY %d", ret_val);	       
            sslw_parse_packet(ae, direction, &po);
   
            /* Don't write dropped data */
            if (po.flags & PO_DROPPED)
	       continue;
DEBUG_MSG("-- conn  write --");	    
		  
	    ret_val = sslw_write_data(ae, !direction, &po);
	    BREAK_ON_ERROR(ret_val, ae);
DEBUG_MSG("-- conn end --");	    
 
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

