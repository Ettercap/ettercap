
#ifndef EC_FORMAT_H
#define EC_FORMAT_H


extern int hex_format(const u_char *buf, size_t len, u_char *dst);

extern int hex_len(int len);

#define HEX_CHAR_PER_LINE   16


#endif

/* EOF */

// vim:ts=3:expandtab

