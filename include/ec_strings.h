
/* $Id: ec_strings.h,v 1.9 2004/06/25 14:11:59 alor Exp $ */

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
extern size_t strlen_utf8(const char *s);
extern char * ec_strtok(char *s, const char *delim, char **ptrptr);

#define strtok(x,y) DON_T_USE_STRTOK_DIRECTLY_USE__EC_STRTOK__INSTEAD

#endif

/* EOF */

// vim:ts=3:expandtab

