
#ifndef EC_STRINGS_H
#define EC_STRINGS_H

#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#else
   extern int isprint(int c);
#endif

extern int match_pattern(const char *s, const char *pattern);
extern int base64_decode(char *bufplain, const char *bufcoded);
   

#endif

/* EOF */

// vim:ts=3:expandtab

