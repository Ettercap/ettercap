/*
    ettercap -- string manipulation functions

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
#include <ec_sleep.h>

#include <ctype.h>

/* protos... */

#ifndef HAVE_CTYPE_H
   int isprint(int c);
#endif
static int hextoint(int c);

/*******************************************/

/* implement the function if it is not available */
#ifndef HAVE_CTYPE_H
int isprint(int c)
{
   return ( (c > 31 && c < 127) ? 1 : 0 );
}
#endif

/* Pattern matching code from OpenSSH. */

int match_pattern(const char *s, const char *pattern)
{
   for (;;) {
      if (!*pattern) return (!*s);

      if (*pattern == '*') {
         pattern++;

         if (!*pattern) return (1);

         if (*pattern != '?' && *pattern != '*') {
            for (; *s; s++) {
               if (*s == *pattern && match_pattern(s + 1, pattern + 1))
                  return (1);
            }
            return (0);
         }
         for (; *s; s++) {
            if (match_pattern(s, pattern))
               return (1);
         }
         return (0);
      }
      if (!*s) return (0);

      if (*pattern != '?' && *pattern != *s)
         return (0);

      s++;
      pattern++;
   }
   /* NOTREACHED */
}

/* stolen from ap_base64.c (apache source code) */

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};


int base64_decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4)
    {
      *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
      *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
      *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
      bufin += 4;
      nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1)
      *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);

    if (nprbytes > 2)
      *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);

    if (nprbytes > 3)
      *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);

    nbytesdecoded -= (4 - nprbytes) & 3;

    bufplain[nbytesdecoded] = '\0';
    return nbytesdecoded;
}


/* adapted from magic.c part of dsniff <dugsong@monkey.org> source code... */

/* 
 * convert an HEX rapresentation into int
 */
static int hextoint(int c)
{
   if (!isascii((int) c))       
      return (-1);
   
   if (isdigit((int) c))        
      return (c - '0');
   
   if ((c >= 'a') && (c <= 'f'))   
      return (c + 10 - 'a');
   
   if ((c >= 'A') && (c <= 'F'))   
      return (c + 10 - 'A');

   return (-1);
}

/* 
 * convert the escaped string into a binary one
 */
int strescape(char *dst, char *src, size_t len)
{
   char  *olddst = dst;
   char  *oldsrc = src;
   int   c;
   int   val;

   while ((c = *src++) != '\0' && (size_t)(src - oldsrc) <= len) {
      if (c == '\\') {
         switch ((c = *src++)) {
            case '\0':
               goto strend;
            default:
               *dst++ = (char) c;
               break;
            case 'n':
               *dst++ = '\n';
               break;
            case 'r':
               *dst++ = '\r';
               break;
            case 'b':
               *dst++ = '\b';
               break;
            case 't':
               *dst++ = '\t';
               break;
            case 'f':
               *dst++ = '\f';
               break;
            case 'v':
               *dst++ = '\v';
               break;
            /* \ and up to 3 octal digits */
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
               val = c - '0';
               c = *src++;  
               /* try for 2 */
               if (c >= '0' && c <= '7') {
                  val = (val << 3) | (c - '0');
                  c = *src++;  
                  /* try for 3 */
                  if (c >= '0' && c <= '7')
                     val = (val << 3) | (c - '0');
                  else 
                     if (src > oldsrc) /* protect against buffer underflow */
                        --src;
               } else 
                  if (src > oldsrc) /* protect against buffer underflow */
                     --src;
               *dst++ = (char) val;
               break;

            case 'x':
               val = 'x';      /* Default if no digits */
               c = hextoint(*src++);     /* Get next char */
               if (c >= 0) {
                       val = c;
                       c = hextoint(*src++);
                       if (c >= 0) 
                          val = (val << 4) + c;
                       else if (src > oldsrc) /* protect against buffer underflow */
                             --src;
               } else if (src > oldsrc) /* protect against buffer underflow */
                     --src;
               *dst++ = (char) val;
               break;
         }
      } else if (c == 8 || c == 263) {  /* the backspace */
         if (dst > oldsrc) /* protect against buffer underflow */
            dst--;
      }
      else
         *dst++ = (char) c;
   }

strend:
   *dst = '\0';

   return (dst - olddst);
}


/*
 * replace 's' with 'd' in the string 'text'
 * text will be realloc'ed, so a pointer is needed
 * and stack based array can't be used
 */
int str_replace(char **text, const char *s, const char *d)
{
   size_t slen = strlen(s);
   size_t dlen = strlen(d);
   int diff = dlen - slen;
   char *p, *q = *text;
   size_t size;

   /* the search string does not exist */
   if (strstr(*text, s) == NULL)
      return -E_NOTFOUND;
   
   /* search all the occurrence of 's' */
   while ( (p = strstr(q, s)) != NULL ) {

      /* the new size */
      if (diff > 0)
         size = strlen(q) + diff + 1;
      else 
         size = strlen(q) + 1;
     
      SAFE_REALLOC(*text, size);
      
      q = *text;
      
      /* 
       * make sure the pointer p is within the *text memory.
       * realloc may have moved it...
       */
      p = strstr(q, s);

      if (p==NULL)
		continue;
      /* do the actual replacement */
      memmove(p + dlen, p + slen, strlen(p + slen) + 1);
      memcpy(p, d, dlen);
      /* avoid recursion on substituted string */
      q = p + dlen;
   }
   
   return E_SUCCESS;
}


/* 
 * Calculate the correct length of characters in an UTF-8 encoded string. 
 */
size_t strlen_utf8(const char *s)
{
   u_char c;
   size_t len = 0;
 
   while ((c = *s++)) {
      if ((c & 0xC0) != 0x80)
         ++len;
   }

   return len;
}


/*
 * a reentrant version of strtok
 */
char * ec_strtok(char *s, const char *delim, char **ptrptr)
{
#ifdef HAVE_STRTOK_R 
   return strtok_r(s, delim, ptrptr);
#else
   #warning unsafe strtok
   /* to avoid the warning on this function (the wrapper macro) */
   #undef strtok
   return strtok(s, delim);
#endif
}

/*
 * simulate the getchar() on a buffer instead of on the stdin.
 * also simulate sleep with s(x) for x seconds.
 */
char getchar_buffer(char **buf)
{
   char ret;

   DEBUG_MSG("getchar_buffer: %s", *buf);
   
   /* the buffer is empty, do nothing */
   if (**buf == 0)
      return 0;

   /* simulate the sleep if we find s(x) */
   if (*(*buf + 0) == 's' && *(*buf + 1) == '(') {
      char *p;
      int time = 0;
      
      p = strchr(*buf, ')');
      if (p != NULL) {

         *p = '\0';

         /* get the number of seconds to wait */
         time = atoi(*buf + 2);

         DEBUG_MSG("getchar_buffer: sleeping %d secs", time);

         /* move the buffer after the s(x) */
         *buf = p + 1;

         ec_usleep(SEC2MICRO(time));
      }
   }
   
   /* get the first char of the buffer */
   ret = *buf[0];

   /* increment the buffer pointer */
   *buf = *buf + 1;
   
   DEBUG_MSG("getchar_buffer: returning %c", ret);
   
   return ret;
}

/* convert a string of hex values into an array of bytes */
int str_hex_to_bytes(char *string, u_char *bytes)
{
   char value[3]; /* two for the hex and the NULL terminator */
   unsigned int value_bin;
   u_int i;
   size_t slen;

   slen = strlen(string);
   for (i = 0; i < slen; i++) {
      strncpy(value, string + i*2, 2);
      if (sscanf(value, "%02X", &value_bin) != 1)
         return -E_INVALID;
      bytes[i] = value_bin & 0x000000FF;
   }

   return 0;
}


/* print a binary string in hex format */
char * str_tohex(u_char *bin, size_t len, char *dst, size_t dst_len)
{
   size_t i;

   memset(dst, 0, dst_len);

   for (i = 0; i < len; i++)
      sprintf(dst + i*2, "%02X", bin[i]);

   return dst;
}

/* split ip from port */
int ec_strsplit_ipport(char *input, char *ip, u_int16 *port)
{
   static char ip_tmp[MAX_ASCII_ADDR_LEN];

   /* Format for IPv4: 1.2.3.4:80 */
   if (sscanf(input, "%20[0-9.]:%hu", ip_tmp, port) == 2) {
      strncpy(ip, ip_tmp, strlen(ip_tmp)+1);
      return E_SUCCESS;
   }

   /* Format for IPv6: [2001:db8::1]:80 */
   if (sscanf(input, "[%40[0-9a-fA-F:.]]:%hu", ip_tmp, port) == 2) {
      strncpy(ip, ip_tmp, strlen(ip_tmp)+1);
      return E_SUCCESS;
   }

   DEBUG_MSG("ec_strsplit_ipport(): error splitting ip:port: '%s'\n", input);
   return -E_INVALID;
}

/* duplicate string in all letters lowercase */
const char *ec_strlc(const char *input)
{
   char *output, *ptr;

   ptr = output = strdup(input);
   do {
      *ptr = tolower(*ptr);
   } while (*(ptr++) != 0);

   return output;
}

/* duplicate string in all letters uppercase */
const char *ec_struc(const char *input)
{
   char *output, *ptr;

   ptr = output = strdup(input);
   do {
      *ptr = toupper(*ptr);
   } while (*(ptr++) != 0);

   return output;
}

/* EOF */

// vim:ts=3:expandtab

