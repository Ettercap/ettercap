/*
    ettercap -- data handling module (fingerprints databases etc)

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_file.c,v 1.5 2003/06/21 13:58:42 alor Exp $
*/

#include <ec.h>
#include <ec_file.h>
#include <ec_version.h>

/* protos */

static char * get_full_path(char *dir, char *file);
static char * get_local_path(char *file);
FILE * open_data(char *dir, char *file, char *mode);

/*******************************************/

/*
 * add the prefix to a given filename
 */

static char * get_full_path(char *dir, char *file)
{
   char *filename;
   int len;

   len = strlen(INSTALL_PREFIX) + strlen(dir) + strlen(EC_PROGRAM) + strlen(file) + 4;

   filename = calloc(len, sizeof(char));
   ON_ERROR(filename, NULL, "out of memory");
   
   if (!strcmp(dir, "etc"))
      snprintf(filename, len, "%s/%s/%s", INSTALL_PREFIX, dir, file);
   else
      snprintf(filename, len, "%s/%s/%s/%s", INSTALL_PREFIX, dir, EC_PROGRAM, file);

   DEBUG_MSG("get_full_path -- %s %s", dir, filename);
   
   return filename;
}

/*
 * add the local path to a given filename
 */

static char * get_local_path(char *file)
{
   char *filename;

   filename = calloc(strlen("./share/") + strlen(file) + 1, sizeof(char));
   ON_ERROR(filename, NULL, "out of memory");
   
   sprintf(filename, "./share/%s", file);
   
   DEBUG_MSG("get_local_path -- %s", filename);
   
   return filename;
}


/*
 * opens a file in the share directory.
 * first look in the installation path, then locally.
 */

FILE * open_data(char *dir, char *file, char *mode)
{
   FILE *fd;
   char *filename = NULL;

   filename = get_full_path(dir, file);
  
   DEBUG_MSG("open_data (%s)", filename);
   
   fd = fopen(filename, mode);
   if (fd == NULL) {
      SAFE_FREE(filename);
      filename = get_local_path(file);

      DEBUG_MSG("open_data dropping to %s", filename);
      
      fd = fopen(filename, mode);
      ON_ERROR(fd, NULL, "can't find %s", filename);
   }
 
   SAFE_FREE(filename);
   
   return fd;
}


/* EOF */

// vim:ts=3:expandtab

