/*
    ettercap -- inet_ntop() function for Windows and possibly other targets.

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
#include <ec_inet.h>

#ifndef HAVE_INET_NTOP /* Rest of file */

#if defined(OS_WINDOWS) && !defined(OS_CYGWIN)
  #define SET_EAFNOSUPPORT() WSASetLastError (errno = WSAEAFNOSUPPORT)
#else
  #define SET_EAFNOSUPPORT() errno = EAFNOSUPPORT
#endif

/*
 * Format an IPv4 address, more or less like inet_ntoa().
 *
 * Returns `dst' (as a const)
 * Note:
 *  - uses no statics
 *  - takes a u_char* not an in_addr as input
 */
static const char *inet_ntop4 (const u_char *src, char *dst, size_t size)
{
  const char *addr = inet_ntoa (*(struct in_addr*)src);

  if (strlen(addr) >= size)
  {
    errno = ENOSPC;
    return (NULL);
  }
  return strcpy (dst, addr);
}

/*
 * Convert IPv6 binary address into presentation (printable) format.
 */
static const char *inet_ntop6 (const u_char *src, char *dst, size_t size)
{
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  char   tmp [sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
  char  *tp;
  u_long words [IN6ADDRSZ / INT16SZ];
  int    i;
  struct {
    long base;
    long len;
  } best, cur;

  /* Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, 0, sizeof(words));
  for (i = 0; i < IN6ADDRSZ; i++)
      words[i/2] |= (src[i] << ((1 - (i % 2)) << 3));

  best.base = cur.base = -1;
  best.len = cur.len = 0;

  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
  {
    if (words[i] == 0)
    {
      if (cur.base == -1)
           cur.base = i, cur.len = 1;
      else cur.len++;
    }
    else if (cur.base != -1)
    {
      if (best.base == -1 || cur.len > best.len)
         best = cur;
      cur.base = -1;
    }
  }
  if ((cur.base != -1) && (best.base == -1 || cur.len > best.len))
     best = cur;
  if (best.base != -1 && best.len < 2)
     best.base = -1;

  /* Format the result.
   */
  tp = tmp;
  for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++)
  {
    /* Are we inside the best run of 0x00's?
     */
    if (best.base != -1 && i >= best.base && i < (best.base + best.len))
    {
      if (i == best.base)
         *tp++ = ':';
      continue;
    }

    /* Are we following an initial run of 0x00s or any real hex?
     */
    if (i != 0)
       *tp++ = ':';

    /* Is this address an encapsulated IPv4?
     */
    if (i == 6 && best.base == 0 &&
        (best.len == 6 || (best.len == 5 && words[5] == 0xffff)))
    {
      if (!inet_ntop4(src+12, tp, sizeof(tmp) - (tp - tmp)))
      {
        errno = ENOSPC;
        return (NULL);
      }
      tp += strlen(tp);
      break;
    }
    tp += sprintf (tp, "%lX", words[i]);
  }

  /* Was it a trailing run of 0x00's?
   */
  if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
     *tp++ = ':';
  *tp++ = '\0';

  /* Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) > size)
  {
    errno = ENOSPC;
    return (NULL);
  }
  return strcpy (dst, tmp);
  return (NULL);
}

/*
 * Convert a network format address to presentation format.
 *
 * Returns pointer to presentation format address (`dst'),
 * Returns NULL on error (see errno).
 */
const char *inet_ntop (int af, const void *src, char *buf, size_t size)
{
  switch (af)
  {
    case AF_INET:
         return inet_ntop4 ((const u_char*)src, buf, size);
    case AF_INET6:
         return inet_ntop6 ((const u_char*)src, buf, size);
    default:
         SET_EAFNOSUPPORT();
         return (NULL);
  }
}
#endif  /* HAVE_INET_NTOP */
