
/* $Id: ec_file.h,v 1.9 2004/06/27 12:51:01 alor Exp $ */

#ifndef EC_FILE_H
#define EC_FILE_H

extern FILE * open_data(char *dir, char *file, char *mode);
extern char * get_full_path(const char *dir, const char *file);
extern char * get_local_path(const char *file);

#define MAC_FINGERPRINTS   "etter.finger.mac"
#define TCP_FINGERPRINTS   "etter.finger.os"
#define SERVICES_NAMES     "etter.services"
#define ETTER_CONF         "etter.conf"
#define ETTER_DNS          "etter.dns"
#define ETTER_FIELDS       "etter.fields"
#define CERT_FILE          "etter.ssl.crt"

/* fopen modes */
#define FOPEN_READ_TEXT   "r"                                                                   
#define FOPEN_READ_BIN    "rb"                                                                   
#define FOPEN_WRITE_TEXT  "w"                                                                   
#define FOPEN_WRITE_BIN   "wb"

#endif

/* EOF */

// vim:ts=3:expandtab

