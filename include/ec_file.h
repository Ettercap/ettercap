
/* $Id: ec_file.h,v 1.4 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_FILE_H
#define EC_FILE_H

extern FILE * open_data(char *dir, char *file, char *mode);

#define MAC_FINGERPRINTS   "etter.finger.mac"
#define TCP_FINGERPRINTS   "etter.finger.os"
#define SERVICES_NAMES     "etter.services"
#define ETTER_CONF         "etter.conf"


#endif

/* EOF */

// vim:ts=3:expandtab

