
#ifndef EC_FORMAT_H
#define EC_FORMAT_H

#define HEX_CHAR_PER_LINE   16

extern int hex_len(int len);
extern int hex_format(const u_char *buf, size_t len, u_char *dst);
extern int ascii_format(const u_char *buf, size_t len, u_char *dst);
extern int text_format(const u_char *buf, size_t len, u_char *dst);
extern int ebcdic_format(const u_char *buf, size_t len, u_char *dst);
extern int html_format(const u_char *buf, size_t len, u_char *dst);
extern int bin_format(const u_char *buf, size_t len, u_char *dst);
extern int zero_format(const u_char *buf, size_t len, u_char *dst);

extern void set_format(char *format);


#endif

/* EOF */

// vim:ts=3:expandtab

