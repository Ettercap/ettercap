/*
    etterfilter -- the actual compiler

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

    $Id: ef_output.c,v 1.4 2003/09/28 21:07:49 alor Exp $
*/

#include <ef.h>
#include <ef_functions.h>
#include <ec_filter.h>
#include <ec_version.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


/* protos */

int write_output(void);

/*******************************************/

int write_output(void)
{
   int fd;
   struct filter_op *fop;
   struct filter_header fh;
   size_t ninst;

   /* conver the tree to an array of filter_op */
   ninst = compile_tree(&fop);

   if (fop == NULL)
      return -ENOTHANDLED;

   fprintf(stdout, "Writing output to \"%s\"...", GBL_OPTIONS.output_file);
   fflush(stdout);
   
   /* create the file */
   fd = open(GBL_OPTIONS.output_file, O_CREAT | O_RDWR | O_TRUNC, 0644);
   ON_ERROR(fd, -1, "Can't create file %s", GBL_OPTIONS.output_file);

   /* write the header */
   fh.magic = htons(EC_FILTER_MAGIC);
   strncpy(fh.version, EC_VERSION, sizeof(fh.version));
   
   write(fd, &fh, sizeof(struct filter_header));
   
   /* write the instructions */
   write(fd, fop, sizeof(struct filter_op) * ninst);

   close(fd);
   
   fprintf(stdout, "done.\n\n");
   
   return ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab

