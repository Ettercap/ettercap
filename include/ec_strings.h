
/* $Id: ec_strings.h,v 1.7 2003/09/22 17:52:42 alor Exp $ */

#ifndef EC_STRINGS_H
#define EC_STRINGS_H

#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#else
   extern int isprint(int c);
#endif

#ifndef HAVE_STRLCAT
   #include <missing/strlcat.h>
#endif
#ifndef HAVE_STRLCPY 
   #include <missing/strlcpy.h>
#endif
#ifndef HAVE_STRSEP 
   #include <missing/strsep.h>
#endif
#ifndef HAVE_STRCASESTR 
   #include <missing/strcasestr.h>
#endif
#ifndef HAVE_MEMMEM
   #include <missing/memmem.h>
#endif

extern int match_pattern(const char *s, const char *pattern);
extern int base64_decode(char *bufplain, const char *bufcoded);
extern int strescape(char *dst, char *src);
extern int str_replace(char **text, const char *s, const char *d);   

#endif

/* EOF */

// vim:ts=3:expandtab

