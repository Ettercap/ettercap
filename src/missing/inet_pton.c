/*
    ettercap -- inet_pton() function for Windows and possibly other targets.

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

#ifndef HAVE_INET_PTON

#ifdef OS_WINDOWS
  #define SET_EAFNOSUPPORT() WSASetLastError (errno = WSAEAFNOSUPPORT)
#else
  #define SET_EAFNOSUPPORT() errno = EAFNOSUPPORT
#endif

/*
 * int inet_pton4(src, dst)
 *      like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *      1 if `src' is a valid dotted quad, else 0.
 * notice:
 *      does not touch `dst' unless it's returning 1.
 * author:
 *      Paul Vixie, 1996.
 */
static int inet_pton4 (const char *src, u_char *dst)
{
  static const char digits[] = "0123456789";
  int    saw_digit, octets, ch;
  u_char tmp[INADDRSZ], *tp;

  saw_digit = octets = 0;
  tp = tmp;
  *tp = 0;

  while ((ch = *src++) != '\0')
  {
    const char *pch = strchr (digits, ch);

    if (pch)
    {
      u_int d2 = *tp * 10 + (pch - digits);

      if (d2 > 255)
         return (0);
      *tp = d2;
      if (!saw_digit)
      {
        if (++octets > 4)
           return (0);
        saw_digit = 1;
      }
    }
    else if (ch == '.' && saw_digit)
    {
      if (octets == 4)
         return (0);
      *++tp = 0;
      saw_digit = 0;
    }
    else
      return (0);
  }
  if (octets < 4)
     return (0);
  memcpy (dst, tmp, INADDRSZ);
  return (1);
}

/* int
 * inet_pton6(src, dst)
 *      convert presentation level address to network order binary form.
 * return:
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *      (1) does not touch `dst' unless it's returning 1.
 *      (2) :: in a full address is silently ignored.
 * credit:
 *      inspired by Mark Andrews.
 * author:
 *      Paul Vixie, 1996.
 */
static int inet_pton6 (const char *src, u_char *dst)
{
  static const char xdigits_l[] = "0123456789abcdef";
  static const char xdigits_u[] = "0123456789ABCDEF";
  u_char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
  const char *xdigits, *curtok;
  int   ch, saw_xdigit;
  u_int val;

  tp = tmp;
  memset (tp, 0, IN6ADDRSZ);
  endp = tp + IN6ADDRSZ;
  colonp = NULL;

  /* Leading :: requires some special handling. */
  if (*src == ':' && *++src != ':')
     return (0);

  curtok = src;
  saw_xdigit = 0;
  val = 0;

  while ((ch = *src++) != '\0')
  {
    const char *pch = strchr (xdigits = xdigits_l, ch);

    if (!pch)
       pch = strchr (xdigits = xdigits_u, ch);
    if (pch)
    {
      val <<= 4;
      val |= (pch - xdigits);
      if (val > 0xffff)
         return (0);
      saw_xdigit = 1;
      continue;
    }
    if (ch == ':')
    {
      curtok = src;
      if (!saw_xdigit)
      {
        if (colonp)
           return (0);
        colonp = tp;
        continue;
      }
      if (tp + INT16SZ > endp)
         return (0);
      *tp++ = (u_char) (val >> 8) & 0xff;
      *tp++ = (u_char) val & 0xff;
      saw_xdigit = 0;
      val = 0;
      continue;
    }
    if (ch == '.' && ((tp + INADDRSZ) <= endp) && inet_pton4(curtok, tp) > 0)
    {
      tp += INADDRSZ;
      saw_xdigit = 0;
      break;                    /* '\0' was seen by inet_pton4(). */
    }
    return (0);
  }
  if (saw_xdigit)
  {
    if (tp + INT16SZ > endp)
      return (0);
    *tp++ = (u_char) (val >> 8) & 0xff;
    *tp++ = (u_char) val & 0xff;
  }

  if (colonp)
  {
    /* Since some memmove()'s erroneously fail to handle
     * overlapping regions, we'll do the shift by hand.
     */
    const int n = tp - colonp;
    int i;

    for (i = 1; i <= n; i++)
    {
      endp [-i] = colonp [n-i];
      colonp [n-i] = 0;
    }
    tp = endp;
  }
  if (tp != endp)
     return (0);
  memcpy (dst, tmp, IN6ADDRSZ);
  return (1);
}

/*
 * int inet_pton(af, src, dst)
 *      convert from presentation format (which usually means ASCII printable)
 *      to network format (which is usually some kind of binary format).
 * return:
 *      1 if the address was valid for the specified address family
 *      0 if the address wasn't valid (`dst' is untouched in this case)
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *      Paul Vixie, 1996.
 */
int inet_pton (int af, const char *src, void *dst)
{
  switch (af)
  {
    case AF_INET:
         return inet_pton4 (src, (u_char*)dst);
    case AF_INET6:
         return inet_pton6 (src, (u_char*)dst);
    default:
         SET_EAFNOSUPPORT();
         return (-1);
  }
}
#endif /* HAVE_INET_PTON */
