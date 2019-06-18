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

*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_session.h>
#include <ec_hook.h>
#include <ec_dissect.h>
#include <ec_threads.h>
#include <ec_sslwrap.h>
#include <ec_file.h>
#include <ec_version.h>
#include <ec_socket.h>
#include <ec_utils.h>
#include <ec_sleep.h>
#include <ec_redirect.h>

#include <sys/types.h>

#ifdef OS_LINUX
   #include <linux/netfilter_ipv4.h>
#endif
#if defined OS_LINUX && defined WITH_IPV6
   #include <linux/netfilter_ipv6/ip6_tables.h>
#endif

#include <fcntl.h>
#include <pthread.h>

// XXX - check if we have poll.h
#ifdef HAVE_SYS_POLL_H
   #include <sys/poll.h>
#endif

/* don't include kerberos. RH sux !! */
#define OPENSSL_NO_KRB5 1
#include <openssl/ssl.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define HAVE_OPAQUE_RSA_DSA_DH 1 /* since 1.1.0 -pre5 */
#endif

#define BREAK_ON_ERROR(x,y,z) do {  \
   if (x == -E_INVALID) {            \
      SAFE_FREE(z.DATA.disp_data);  \
      sslw_initialize_po(&z, z.DATA.data); \
      z.len = 64;                   \
      z.L4.flags = TH_RST;          \
      packet_disp_data(&z, z.DATA.data, z.DATA.len); \
      sslw_parse_packet(y, SSL_SERVER, &z); \
      sslw_wipe_connection(y);      \
      SAFE_FREE(z.DATA.data);       \
      SAFE_FREE(z.DATA.disp_data);  \
      ec_thread_exit();             \
   }                                \
} while(0)

/* globals */

static LIST_HEAD (, listen_entry) listen_ports;

struct listen_entry {
   int fd;
   int fd6;
   u_int16 sslw_port;   /* Port where we want to wrap SSL */
   u_int16 redir_port;  /* Port where accepts connections */
   u_char status;       /* Use directly SSL or not */
   char *name;
   LIST_ENTRY (listen_entry) next;
};

struct accepted_entry {
   int32 fd[2];   /* 0->Client, 1->Server */
   u_int16 port[2];
   struct ip_addr ip[2];
   SSL *ssl[2];
   u_char status;
   X509 *cert;
   #define SSL_CLIENT 0
   #define SSL_SERVER 1
};

/* Session identifier 
 * It has to be of even length for session hash matching */
struct sslw_ident {
   u_int32 magic;
      #define SSLW_MAGIC  0x0501e77e
   struct ip_addr L3_src;
   u_int16 L4_src;
   u_int16 L4_dst;
};
#define SSLW_IDENT_LEN sizeof(struct sslw_ident)

#define SSLW_RETRY 500
#define SSLW_WAIT 10 /* 10 milliseconds */


#define TSLEEP (50*1000) /* 50 milliseconds */

static SSL_CTX *ssl_ctx_client, *ssl_ctx_server;
static EVP_PKEY *global_pk;
static u_int16 number_of_services;
static struct pollfd *poll_fd = NULL;

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
static void sslw_initialize_po(struct packet_object *po, u_char *p_data);
static int sslw_match(void *id_sess, void *id_curr);
static void sslw_create_session(struct ec_session **s, struct packet_object *po);
static size_t sslw_create_ident(void **i, struct packet_object *po);            
static void sslw_hook_handled(struct packet_object *po);
static X509 *sslw_create_selfsigned(X509 *serv_cert);
static void ssl_wrap_fini(void);
static int sslw_ssl_connect(SSL *ssl_sk);
static int sslw_ssl_accept(SSL *ssl_sk);
static int sslw_remove_sts(struct packet_object *po);

/*******************************************/

/* 
 * Register a new ssl wrapper 
 */
void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status)
{
   struct listen_entry *le;
   
   SAFE_CALLOC(le, 1, sizeof(struct listen_entry));
 
   le->sslw_port = port;
   le->status = status;
   le->name = name;

   /* Insert it in the port list where listen for connections */ 
   LIST_INSERT_HEAD(&listen_ports, le, next);    

   dissect_add(name, APP_LAYER_TCP, port, decoder); 
}

/* 
 * Move a ssl_wrapper on another port
 */
void sslw_dissect_move(char *name, u_int16 port)
{
   struct listen_entry *le, *tmp;

   LIST_FOREACH_SAFE(le, &listen_ports, next, tmp) 
      if(!strcmp(name, le->name)) {
         DEBUG_MSG("sslw_dissect_move: %s [%u]", name, port);
         le->sslw_port = port;
	 
      /* Move to zero means disable */
      if (port == 0) {
         LIST_REMOVE(le, next);
         SAFE_FREE(le);
      }
   }
}

/* 
 * Initialize the ssl wrappers
 */
void ssl_wrap_init(void)
{
   struct listen_entry *le;

   /* disable if the aggressive flag is not set */
   if (!EC_GBL_CONF->aggressive_dissectors) {
      DEBUG_MSG("ssl_wrap_init: not aggressive");
      return;
   }
   
   /* a valid script for the redirection must be set */
   if (!EC_GBL_CONF->redir_command_on) {
      DEBUG_MSG("ssl_wrap_init: no redirect script");
      USER_MSG("SSL dissection needs a valid 'redir_command_on' script in the etter.conf file\n");
      return;
   }

   DEBUG_MSG("ssl_wrap_init");
   sslw_init();
   sslw_bind_wrapper();
   
   /* Add the hook to block real ssl packet going to top half */
   hook_add(HOOK_HANDLED, &sslw_hook_handled);

   number_of_services = 0;
   LIST_FOREACH(le, &listen_ports, next) 
      number_of_services++;

#ifdef WITH_IPV6
   /* with IPv6 enabled we actually duplicate the number of listener sockets */
   number_of_services *= 2;
#endif
   
   SAFE_CALLOC(poll_fd, 1, sizeof(struct pollfd) * number_of_services);

   atexit(ssl_wrap_fini);
}


static void ssl_wrap_fini(void)
{
   struct listen_entry *le, *old;

   DEBUG_MSG("ATEXIT: ssl_wrap_fini");
   /* remove every redirect rule and close listener sockets */
   LIST_FOREACH_SAFE(le, &listen_ports, next, old) {
      close(le->fd);
#ifdef WITH_IPV6
      close(le->fd6);
#endif
      LIST_REMOVE(le, next);
      SAFE_FREE(le);
   }

   SSL_CTX_free(ssl_ctx_server);
   SSL_CTX_free(ssl_ctx_client);

   /* remove redirects */
   ec_redirect_cleanup();

}

/* 
 * SSL thread main function.
 */
EC_THREAD_FUNC(sslw_start)
{
   struct listen_entry *le;
   struct accepted_entry *ae;
   struct sockaddr_storage client_ss;
   struct sockaddr *sa;
   struct sockaddr_in *sa4;
#ifdef WITH_IPV6
   struct sockaddr_in6 *sa6;
#endif
   u_int len = sizeof(client_ss);
   int fd = 0, nfds = 0, i = 0;

   /* variable not used */
   (void) EC_THREAD_PARAM;

   ec_thread_init();

   /* disabled if not aggressive */
   if (!EC_GBL_CONF->aggressive_dissectors)
      return NULL;

   /* a valid script for the redirection must be set */
   if (!EC_GBL_CONF->redir_command_on)
      return NULL;

   DEBUG_MSG("sslw_start: initialized and ready");

   /* set the polling on all registered services */
   LIST_FOREACH(le, &listen_ports, next) {
      poll_fd[nfds].fd = le->fd;
      poll_fd[nfds].events = POLLIN;
#ifdef WITH_IPV6
      nfds++;
      poll_fd[nfds].fd = le->fd6;
      poll_fd[nfds].events = POLLIN;
#endif
      nfds++;
   }

   LOOP {
      poll(poll_fd, nfds, -1);

      /* Find out which file descriptor got active */
      for (i=0; i<nfds; i++) {
         if (!(poll_fd[i].revents & POLLIN))
            continue;

         /* determine listen entry */
         LIST_FOREACH(le, &listen_ports, next) {
            if (poll_fd[i].fd == le->fd) {
               fd = le->fd;
               break;
            }
#ifdef WITH_IPV6
            if (poll_fd[i].fd == le->fd6) {
               fd = le->fd6;
               break;
            }
#endif
         }

         DEBUG_MSG("ssl_wrapper -- got a connection on port %d [%d]", le->redir_port, le->sslw_port);
         SAFE_CALLOC(ae, 1, sizeof(struct accepted_entry));

         ae->fd[SSL_CLIENT] = accept(fd, (struct sockaddr *)&client_ss, &len);
         
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
         sa = (struct sockaddr *)&client_ss;
         switch (sa->sa_family) {
            case AF_INET:
               sa4 = (struct sockaddr_in *)&client_ss;
               ae->port[SSL_CLIENT] = sa4->sin_port;
               ip_addr_init(&(ae->ip[SSL_CLIENT]), AF_INET, (u_char *)&(sa4->sin_addr.s_addr));
               break;
#ifdef WITH_IPV6
            case AF_INET6:
               sa6 = (struct sockaddr_in6 *)&client_ss;
               ae->port[SSL_CLIENT] = sa6->sin6_port;
               ip_addr_init(&(ae->ip[SSL_CLIENT]), AF_INET6, (u_char *)&(sa6->sin6_addr.s6_addr));
               break;
#endif
         }

         /* create a detached thread */
         ec_thread_new_detached("sslw_child", "ssl child", &sslw_child, ae, 1);
      }
   }

   return NULL;
   
}	 

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
     
   /* If it's an ssl packet don't forward */
   po->flags |= PO_DROPPED;
   
   /* If it's a new connection */
   if ( (po->flags & PO_FORWARDABLE) && 
        (po->L4.flags & TH_SYN) &&
        !(po->L4.flags & TH_ACK) ) {
	
      sslw_create_session(&s, PACKET);

#ifndef OS_LINUX
      /* Remember the real destination IP */
      memcpy(s->data, &po->L3.dst, sizeof(struct ip_addr));
      session_put(s);
#else
	SAFE_FREE(s); /* Just get rid of it */
#endif
   } else /* Pass only the SYN for conntrack */
      po->flags |= PO_IGNORE;
}


/* 
 * Check if this packet is for ssl wrappers 
 */
static int sslw_is_ssl(struct packet_object *po)
{
   struct listen_entry *le;
   
   /* If it's already coming from ssl wrapper 
    * or the connection is not TCP */ 
   if (po->flags & PO_FROMSSL || po->L4.proto != NL_TYPE_TCP) 
      return 0;

   LIST_FOREACH(le, &listen_ports, next) {
      if (ntohs(po->L4.dst) == le->sslw_port ||
          ntohs(po->L4.src) == le->sslw_port)
         return 1;
   }
   return 0;
}


/*
 * Bind all registered wrappers to free ports 
 * and isnert redirects.
 */ 
static void sslw_bind_wrapper(void)
{
   u_int16 bind_port = EC_MAGIC_16; 
   struct listen_entry *le;
   struct sockaddr_in sa_in;
#ifdef WITH_IPV6
   struct sockaddr_in6 sa_in6;
   int optval = 1;
#endif

   LIST_FOREACH(le, &listen_ports, next) {

      le->fd = socket(AF_INET, SOCK_STREAM, 0);
      if (le->fd == -1)
        FATAL_ERROR("Unable to create socket in sslw_bind_wrapper()");
      memset(&sa_in, 0, sizeof(sa_in));
      sa_in.sin_family = AF_INET;
      sa_in.sin_addr.s_addr = INADDR_ANY;

      do {
         bind_port++;
         sa_in.sin_port = htons(bind_port);
         le->redir_port = bind_port;
      } while ( bind(le->fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0);

      DEBUG_MSG("sslw - bind %d on %d", le->sslw_port, le->redir_port);
      if(listen(le->fd, 100) == -1)
        FATAL_ERROR("Unable to accept connections for socket");

#ifdef WITH_IPV6
      /* create & bind IPv6 socket on the same port */
      le->fd6 = socket(AF_INET6, SOCK_STREAM, 0);
      if (le->fd6 == -1)
        FATAL_ERROR("Unable to create socket in sslw_bind_wrapper() for IPv6");
      memset(&sa_in6, 0, sizeof(sa_in6));
      sa_in6.sin6_family = AF_INET6;
      sa_in6.sin6_addr = in6addr_any;
      sa_in6.sin6_port = htons(bind_port);

      /* we only listen on v6 as we use dedicated sockets per AF */
      if (setsockopt(le->fd6, IPPROTO_IPV6, IPV6_V6ONLY,
               &optval, sizeof(optval)) == -1) 
         FATAL_ERROR("Unable to set IPv6 socket to IPv6 only in sslw_bind_wrapper(): %s", 
               strerror(errno));

      /* bind to IPv6 on the same port as the IPv4 socket */
      if (bind(le->fd6, (struct sockaddr *)&sa_in6, sizeof(sa_in6)) == -1)
         FATAL_ERROR("Unable to bind() IPv6 socket to port %d in sslw_bind_wrapper(): %s",
               bind_port, strerror(errno));

      if(listen(le->fd6, 100) == -1)
        FATAL_ERROR("Unable to accept connections for IPv6 socket");
#else
      /* properly init fd even if unused - necessary for select call */
      le->fd6 = 0;
#endif

      if (ec_redirect(EC_REDIR_ACTION_INSERT, le->name,
               EC_REDIR_PROTO_IPV4, NULL, NULL,
               le->sslw_port, le->redir_port) != E_SUCCESS)
        FATAL_ERROR("Can't insert firewall redirects");

#ifdef WITH_IPV6
      if (ec_redirect(EC_REDIR_ACTION_INSERT, le->name,
               EC_REDIR_PROTO_IPV6, NULL, NULL,
               le->sslw_port, le->redir_port) != E_SUCCESS)
        FATAL_ERROR("Can't insert firewall redirects");
#endif

   }
}

/* 
 * Create TCP a connection to the real SSL server 
 */
static int sslw_sync_conn(struct accepted_entry *ae)
{      
   if(sslw_get_peer(ae) != E_SUCCESS)
         return -E_INVALID;
	 
   if(sslw_connect_server(ae) != E_SUCCESS)
         return -E_INVALID;

   /* set nonbloking socket */
   set_blocking(ae->fd[SSL_CLIENT], 0);
   set_blocking(ae->fd[SSL_SERVER], 0);

   return E_SUCCESS;
}


/* 
 * Perform a blocking SSL_connect with a
 * configurable timeout on a non-blocing socket 
 */
static int sslw_ssl_connect(SSL *ssl_sk)
{ 
   int loops = (EC_GBL_CONF->connect_timeout * 10e5) / TSLEEP;
   int ret, ssl_err;

   do {
      /* connect to the server */
      if ( (ret = SSL_connect(ssl_sk)) == 1)
         return E_SUCCESS;

      ssl_err = SSL_get_error(ssl_sk, ret);
      
      /* there was an error... */
      if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) 
         return -E_INVALID;
      
      /* sleep a quirk of time... */
      ec_usleep(TSLEEP);
   } while(loops--);

   return -E_INVALID;
}


/* 
 * Perform a blocking SSL_accept with a
 * configurable timeout on a non-blocing socket 
 */
static int sslw_ssl_accept(SSL *ssl_sk)
{ 
   int loops = (EC_GBL_CONF->connect_timeout * 10e5) / TSLEEP;
   int ret, ssl_err;

   do {
      /* accept the ssl connection */
      if ( (ret = SSL_accept(ssl_sk)) == 1)
         return E_SUCCESS;

      ssl_err = SSL_get_error(ssl_sk, ret);
      
      /* there was an error... */
      if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) 
         return -E_INVALID;
      
      /* sleep a quirk of time... */
      ec_usleep(TSLEEP);
   } while(loops--);

   return -E_INVALID;
}


/* 
 * Create an SSL connection to the real server.
 * Grab server certificate and create a fake one
 * for the poor client.
 * Then accept the SSL connection from the client.
 */   
static int sslw_sync_ssl(struct accepted_entry *ae) 
{   

   X509 *server_cert;
   
   ae->ssl[SSL_SERVER] = SSL_new(ssl_ctx_server);
   SSL_set_connect_state(ae->ssl[SSL_SERVER]);
   SSL_set_fd(ae->ssl[SSL_SERVER], ae->fd[SSL_SERVER]);
   ae->ssl[SSL_CLIENT] = SSL_new(ssl_ctx_client);
   SSL_set_fd(ae->ssl[SSL_CLIENT], ae->fd[SSL_CLIENT]);
    
   if (sslw_ssl_connect(ae->ssl[SSL_SERVER]) != E_SUCCESS) 
      return -E_INVALID;

   /* XXX - NULL cypher can give no certificate */
   if ( (server_cert = SSL_get_peer_certificate(ae->ssl[SSL_SERVER])) == NULL) {
      DEBUG_MSG("Can't get peer certificate");
      return -E_INVALID;
   }

   if (!EC_GBL_OPTIONS->ssl_cert) {
   	/* Create the fake certificate */
   	ae->cert = sslw_create_selfsigned(server_cert);  
   	X509_free(server_cert);

   	if (ae->cert == NULL)
      		return -E_INVALID;

   	SSL_use_certificate(ae->ssl[SSL_CLIENT], ae->cert);

   }
   
   if (sslw_ssl_accept(ae->ssl[SSL_CLIENT]) != E_SUCCESS) 
      return -E_INVALID;


   return E_SUCCESS;   
}


/* 
 * Take the IP address of the server 
 * that the client wants to talk to.
 */
static int sslw_get_peer(struct accepted_entry *ae)
{

/* If on Linux, we can just get the SO_ORIGINAL_DST from getsockopt() no need for this loop
   nonsense.
*/
#ifndef OS_LINUX
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
   for (i=0; i<SSLW_RETRY && session_get_and_del(&s, ident, SSLW_IDENT_LEN)!=E_SUCCESS; i++)
      ec_usleep(MILLI2MICRO(SSLW_WAIT));

   if (i==SSLW_RETRY) {
      SAFE_FREE(ident);
      return -E_INVALID;
   }
   
   /* Remember the server IP address in the sessions */
   memcpy(&ae->ip[SSL_SERVER], s->data, sizeof(struct ip_addr));
   
   SAFE_FREE(s->data);
   SAFE_FREE(s);
   SAFE_FREE(ident);
#else
   struct sockaddr_storage ss;
   struct sockaddr_in *sa4;
#if defined WITH_IPV6 && defined HAVE_IP6T_SO_ORIGINAL_DST
   struct sockaddr_in6 *sa6;
#endif
   socklen_t ss_len = sizeof(struct sockaddr_storage);

   switch (ntohs(ae->ip[SSL_CLIENT].addr_type)) {
      case AF_INET:
         if (getsockopt(ae->fd[SSL_CLIENT], SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*)&ss, &ss_len) == -1) {
            WARN_MSG("getsockopt failed: %s", strerror(errno));
            return -E_INVALID;
         }
         sa4 = (struct sockaddr_in *)&ss;
         ip_addr_init(&(ae->ip[SSL_SERVER]), AF_INET, (u_char *)&(sa4->sin_addr.s_addr));
         break;
#if defined WITH_IPV6 && defined HAVE_IP6T_SO_ORIGINAL_DST
      case AF_INET6:
         if (getsockopt(ae->fd[SSL_CLIENT], IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, (struct sockaddr*)&ss, &ss_len) == -1) {
            WARN_MSG("getsockopt failed: %s", strerror(errno));
            return -E_INVALID;
         }
         sa6 = (struct sockaddr_in6 *)&ss;
         ip_addr_init(&(ae->ip[SSL_SERVER]), AF_INET6, (u_char *)&(sa6->sin6_addr.s6_addr));
         break;
#endif
   }

#endif
   return E_SUCCESS;
}


/* 
 * Take the other peer (server) from ssl-decoders' sessions
 * and contact it. 
 * Check if we have to enter SSL state.
 */
static int sslw_connect_server(struct accepted_entry *ae)
{
   char dest_ip[MAX_ASCII_ADDR_LEN];
   
   ip_addr_ntoa(&ae->ip[SSL_SERVER], dest_ip);
 
   /* Standard connection to the server */
   if ((ae->fd[SSL_SERVER] = open_socket(dest_ip, ntohs(ae->port[SSL_SERVER]))) < 0) {
      DEBUG_MSG("Could not open socket");
      return -E_INVALID;
   }
   
   return E_SUCCESS;   
}


/* 
 * Read the data from an accepted connection. 
 * Check if it already entered SSL state.
 */ 
static int sslw_read_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   int len, ret_err;
   
   if (ae->status & SSL_ENABLED)
      len = SSL_read(ae->ssl[direction], po->DATA.data, 1024);
   else       
      //len = socket_recv(ae->fd[direction], po->DATA.data, 1024);
      len = read(ae->fd[direction], po->DATA.data, 1024);

   /* XXX - Check when it returns 0 (it was a <)*/
   if (len <= 0 && (ae->status & SSL_ENABLED)) {
      ret_err = SSL_get_error(ae->ssl[direction], len);
      
      /* XXX - Is it necessary? */
      if (len == 0)
         return -E_INVALID;
	       
      if (ret_err == SSL_ERROR_WANT_READ || ret_err == SSL_ERROR_WANT_WRITE)
         return -E_NOTHANDLED;
      else
         return -E_INVALID;
   }

   /* Only if no ssl */
   if (len < 0) {
      int err = GET_SOCK_ERRNO();

      if (err == EINTR || err == EAGAIN)
         return -E_NOTHANDLED;
      else
         return -E_INVALID;
   }      

   /* XXX - On standard reads, close is 0? (EOF)*/
   if (len == 0) 
      return -E_INVALID;

   po->len = len;
   po->DATA.len = len;
   po->L4.flags |= TH_PSH;

   /* NULL terminate the data buffer */
   po->DATA.data[po->DATA.len] = 0;

   /* remove STS header */ 
   if (direction == SSL_SERVER)
       sslw_remove_sts(po);

   /* create the buffer to be displayed */
   packet_destroy_object(po);
   packet_disp_data(po, po->DATA.data, po->DATA.len);
   
   return E_SUCCESS;
}


/* 
 * Write the data into an accepted connection. 
 * Check if it already entered SSL state.
 */ 
static int sslw_write_data(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   int32 len, packet_len, not_written, ret_err;
   u_char *p_data;

   packet_len = (int32)(po->DATA.len + po->DATA.inject_len);
   p_data = po->DATA.data;

   if (packet_len == 0)
      return E_SUCCESS;

   do {
      not_written = 0;
      /* Write packet data */
      if (ae->status & SSL_ENABLED)
         len = SSL_write(ae->ssl[direction], p_data, packet_len);
      else       
         //len = socket_send(ae->fd[direction], p_data, packet_len);
         len = write(ae->fd[direction], p_data, packet_len);

      if (len <= 0 && (ae->status & SSL_ENABLED)) {
         ret_err = SSL_get_error(ae->ssl[direction], len);
         if (ret_err == SSL_ERROR_WANT_READ || ret_err == SSL_ERROR_WANT_WRITE)
            not_written = 1;
         else
            return -E_INVALID;
      }

      if (len < 0 && !(ae->status & SSL_ENABLED)) {
         int err = GET_SOCK_ERRNO();

         if (err == EINTR || err == EAGAIN)
            not_written = 1;
         else
            return -E_INVALID;
      }      

      /* XXX - does some OS use partial writes for SSL? */
      if (len < packet_len && !not_written ) {
         DEBUG_MSG("SSL-Wrapper partial writes: to be implemented...");
         packet_len -= len;
         p_data += len;
         not_written = 1;
      }
      
      /* XXX - Set a proper sleep time */
      if (not_written)
         ec_usleep(SEC2MICRO(1));
	 	 
   } while (not_written);
         
   return E_SUCCESS;
}


/* 
 * Fill the packet object and put it in 
 * the dissector stack (above protocols decoders)
 */
static void sslw_parse_packet(struct accepted_entry *ae, u_int32 direction, struct packet_object *po)
{
   FUNC_DECODER_PTR(start_decoder);
   int len;

   /* 
    * ssl childs keep the connection alive even if the sniffing thread
    * was stopped. But don't add packets to top-half queue.
    */
   if (!EC_GBL_SNIFF->active)
      return;

   memcpy(&po->L3.src, &ae->ip[direction], sizeof(struct ip_addr));
   memcpy(&po->L3.dst, &ae->ip[!direction], sizeof(struct ip_addr));
   
   po->L4.src = ae->port[direction];
   po->L4.dst = ae->port[!direction];
   
   po->flags |= PO_FROMSSL;
      
   /* get current time */
   gettimeofday(&po->ts, NULL);

   /* calculate if the dest is local or not */
   switch (ip_addr_is_local(&PACKET->L3.src, NULL)) {
      case E_SUCCESS:
         PACKET->PASSIVE.flags &= ~(FP_HOST_NONLOCAL);
         PACKET->PASSIVE.flags |= FP_HOST_LOCAL;
         break;
      case -E_NOTFOUND:
         PACKET->PASSIVE.flags &= ~FP_HOST_LOCAL;
         PACKET->PASSIVE.flags |= FP_HOST_NONLOCAL;
         break;
      case -E_INVALID:
         PACKET->PASSIVE.flags = FP_UNKNOWN;
         break;
   }

   /* Let's start from the last stage of decoder chain */
   start_decoder = get_decoder(APP_LAYER, PL_DEFAULT);
   start_decoder(po->DATA.data, po->DATA.len, &len, po);
}


/* 
 * Remove the connection from the accepted 
 * list and close both sockets.
 */
static void sslw_wipe_connection(struct accepted_entry *ae)
{
   if (ae->ssl[SSL_CLIENT]) 
      SSL_free(ae->ssl[SSL_CLIENT]);

   if (ae->ssl[SSL_SERVER]) 
      SSL_free(ae->ssl[SSL_SERVER]);
 
   close_socket(ae->fd[SSL_CLIENT]);
   close_socket(ae->fd[SSL_SERVER]);

   if (ae->cert)
      X509_free(ae->cert);

   if(ae)
     SAFE_FREE(ae);
}

/* 
 * Initialize a fake PO to be passed to top half
 */
static void sslw_initialize_po(struct packet_object *po, u_char *p_data)
{
   /* 
    * Allocate the data buffer and initialize 
    * fake headers. Headers len is set to 0.
    * XXX - Be sure to not modify these len.
    */
   memset(po, 0, sizeof(struct packet_object));
   if (p_data == NULL) {
      SAFE_CALLOC(po->DATA.data, 1, UINT16_MAX);
   } else {
      if (po->DATA.data != p_data) {
      	  SAFE_FREE(po->DATA.data);
          po->DATA.data = p_data;
      }
   }
      
   po->L2.header  = po->DATA.data; 
   po->L3.header  = po->DATA.data;
   po->L3.options = po->DATA.data;
   po->L4.header  = po->DATA.data;
   po->L4.options = po->DATA.data;
   po->fwd_packet = po->DATA.data;
   po->packet     = po->DATA.data;
   
   po->L3.proto = htons(LL_TYPE_IP);
   po->L3.ttl = 64;
   po->L4.proto = NL_TYPE_TCP;
}


/* 
 * Create a self-signed certificate
 */
static X509 *sslw_create_selfsigned(X509 *server_cert)
{   
   X509 *out_cert;
   X509_EXTENSION *ext;
   int index = 0;
   
   if ((out_cert = X509_new()) == NULL)
      return NULL;

   /* Set out public key, real server name... */
   X509_set_version(out_cert, X509_get_version(server_cert));
   ASN1_INTEGER_set(X509_get_serialNumber(out_cert), EC_MAGIC_32);
   X509_set_notBefore(out_cert, X509_get_notBefore(server_cert));
   X509_set_notAfter(out_cert, X509_get_notAfter(server_cert));
   X509_set_pubkey(out_cert, global_pk);
   X509_set_subject_name(out_cert, X509_get_subject_name(server_cert));
   X509_set_issuer_name(out_cert, X509_get_issuer_name(server_cert));  

   /* Modify the issuer a little bit */ 
   //X509_NAME_add_entry_by_txt(X509_get_issuer_name(out_cert), "L", MBSTRING_ASC, " ", -1, -1, 0);

   index = X509_get_ext_by_NID(server_cert, NID_authority_key_identifier, -1);
   if (index >=0) {
      ext = X509_get_ext(server_cert, index);
#ifdef HAVE_OPAQUE_RSA_DSA_DH
      ASN1_OCTET_STRING* os;
      os = X509_EXTENSION_get_data (ext);
#endif
      if (ext) {
#ifdef HAVE_OPAQUE_RSA_DSA_DH
         os->data[7] = 0xe7;
         os->data[8] = 0x7e;
         X509_EXTENSION_set_data (ext, os);
#else
         ext->value->data[7] = 0xe7;
         ext->value->data[8] = 0x7e;
#endif
         X509_add_ext(out_cert, ext, -1);
      }
   }

   /* Self-sign our certificate */
   if (!X509_sign(out_cert, global_pk, EVP_sha1())) {
      X509_free(out_cert);
      DEBUG_MSG("Error self-signing X509");
      return NULL;
   }
     
   return out_cert;
}


/* 
 * Initialize SSL stuff 
 */
static void sslw_init(void)
{
   SSL *dummy_ssl=NULL;

   SSL_library_init();

   /* Create the two global CTX */
   ssl_ctx_client = SSL_CTX_new(SSLv23_server_method());
   ssl_ctx_server = SSL_CTX_new(SSLv23_client_method());

   ON_ERROR(ssl_ctx_client, NULL, "Could not create client SSL CTX");
   ON_ERROR(ssl_ctx_server, NULL, "Could not create server SSL CTX");

   if(EC_GBL_OPTIONS->ssl_pkey) {
	/* Get our private key from the file specified from cmd-line */
	DEBUG_MSG("Using custom private key %s", EC_GBL_OPTIONS->ssl_pkey);
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx_client, EC_GBL_OPTIONS->ssl_pkey, SSL_FILETYPE_PEM) == 0) {
		FATAL_ERROR("Can't open \"%s\" file : %s", EC_GBL_OPTIONS->ssl_pkey, strerror(errno));
	}

	if (EC_GBL_OPTIONS->ssl_cert) {
		if (SSL_CTX_use_certificate_file(ssl_ctx_client, EC_GBL_OPTIONS->ssl_cert, SSL_FILETYPE_PEM) == 0) {
			FATAL_ERROR("Can't open \"%s\" file : %s", EC_GBL_OPTIONS->ssl_cert, strerror(errno));
		}

		if (!SSL_CTX_check_private_key(ssl_ctx_client)) {
			FATAL_ERROR("Certificate \"%s\" does not match private key \"%s\"", EC_GBL_OPTIONS->ssl_cert, EC_GBL_OPTIONS->ssl_pkey);
		}
	}
   } else {
   	/* Get our private key from our cert file */
   	if (SSL_CTX_use_PrivateKey_file(ssl_ctx_client, INSTALL_DATADIR "/" PROGRAM "/" CERT_FILE, SSL_FILETYPE_PEM) == 0) {
      		DEBUG_MSG("sslw -- SSL_CTX_use_PrivateKey_file -- trying ./share/%s",  CERT_FILE);

      		if (SSL_CTX_use_PrivateKey_file(ssl_ctx_client, "./share/" CERT_FILE, SSL_FILETYPE_PEM) == 0)
         		FATAL_ERROR("Can't open \"./share/%s\" file : %s", CERT_FILE, strerror(errno));
   	}
   }

   dummy_ssl = SSL_new(ssl_ctx_client);
   if ( (global_pk = SSL_get_privatekey(dummy_ssl)) == NULL ) 
      FATAL_ERROR("Can't get private key from file");

   SSL_free(dummy_ssl);   
}


/* 
 * SSL thread child function.
 */

EC_THREAD_FUNC(sslw_child)
{
   struct packet_object po;
   int direction, ret_val, data_read;
   struct accepted_entry *ae;

   ae = (struct accepted_entry *)args;
   ec_thread_init();


   /* We don't want this to accidentally close STDIN */
   ae->fd[SSL_SERVER] = -1;

   /* Contact the real server */
   if (sslw_sync_conn(ae) == -E_INVALID) {
      if (ae->fd[SSL_CLIENT] != -1)
         close_socket(ae->fd[SSL_CLIENT]);
      DEBUG_MSG("FAILED TO FIND PEER");
      SAFE_FREE(ae);
      ec_thread_exit();
   }	    
	    
   if ((ae->status & SSL_ENABLED) && 
      sslw_sync_ssl(ae) == -E_INVALID) {
      sslw_wipe_connection(ae);
      ec_thread_exit();
   }

   /* A fake SYN ACK for profiles */
   sslw_initialize_po(&po, NULL);
   po.len = 64;
   po.L4.flags = (TH_SYN | TH_ACK);
   packet_disp_data(&po, po.DATA.data, po.DATA.len);

   sslw_parse_packet(ae, SSL_SERVER, &po);
   sslw_initialize_po(&po, po.DATA.data);
   
   LOOP {

      data_read = 0;
      for(direction=0; direction<2; direction++) {

         ret_val = sslw_read_data(ae, direction, &po);
         BREAK_ON_ERROR(ret_val,ae,po);
	 
         /* if we have data to read */
         if (ret_val == E_SUCCESS) {
            data_read = 1;


            sslw_parse_packet(ae, direction, &po);

            if (po.flags & PO_DROPPED)
               continue;
	
            ret_val = sslw_write_data(ae, !direction, &po);
            BREAK_ON_ERROR(ret_val,ae,po);
	    
            if ((po.flags & PO_SSLSTART) && !(ae->status & SSL_ENABLED)) {
               ae->status |= SSL_ENABLED; 
               ret_val = sslw_sync_ssl(ae);
               BREAK_ON_ERROR(ret_val,ae,po);
            }
	    
            sslw_initialize_po(&po, po.DATA.data);
         }  
      }

      /* XXX - Set a proper sleep time */
      /* Should we poll both fd's instead of guessing and sleeping? */
      if (!data_read)
         ec_usleep(3000); // 3ms
   }

   return NULL;
}


static int sslw_remove_sts(struct packet_object *po)
{
	u_char *ptr;
	u_char *end;
	u_char *h_end;
	size_t len = po->DATA.len;
	size_t slen = strlen("\r\nStrict-Transport-Security:");

	if (!memmem(po->DATA.data, po->DATA.len, "\r\nStrict-Transport-Security:", slen)) {
		return -E_NOTFOUND;
	}

	ptr = po->DATA.data;
	end = ptr + po->DATA.len;

	len = end - ptr;

	ptr = (u_char*)memmem(ptr, len, "\r\nStrict-Transport-Security:", slen);
	ptr += 2;

	h_end = (u_char*)memmem(ptr, len, "\r\n", 2);
	h_end += 2;

	size_t before_header = ptr - po->DATA.data;
	size_t header_length = h_end - ptr;
	size_t new_len = 0;

	u_char *new_html;
	SAFE_CALLOC(new_html, len, sizeof(u_char));

	BUG_IF(new_html == NULL);

	memcpy(new_html, po->DATA.data, before_header);
	new_len += before_header;

	memcpy(new_html+new_len, h_end, (len - header_length) - before_header);
	new_len += (len - header_length) - before_header;


	memset(po->DATA.data, '\0', po->DATA.len);

	memcpy(po->DATA.data, new_html, new_len);
	po->DATA.len = new_len;

	po->flags |= PO_MODIFIED;


	return E_SUCCESS;

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

   /* return the length of the ident */
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

