
/* $Id: ec_file.h,v 1.8 2004/03/25 21:25:27 lordnaga Exp $ */

#ifndef EC_FILE_H
#define EC_FILE_H

extern FILE * open_data(char *dir, char *file, char *mode);

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

