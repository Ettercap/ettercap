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

    $Id: ef_output.c,v 1.5 2003/10/04 14:58:34 alor Exp $
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
static void print_progress_bar(struct filter_op *fop);

/*******************************************/

int write_output(void)
{
   int fd;
   struct filter_op *fop;
   struct filter_header fh;
   size_t ninst, i;

   /* conver the tree to an array of filter_op */
   ninst = compile_tree(&fop);

   if (fop == NULL)
      return -ENOTHANDLED;

   /* create the file */
   fd = open(GBL_OPTIONS.output_file, O_CREAT | O_RDWR | O_TRUNC, 0644);
   ON_ERROR(fd, -1, "Can't create file %s", GBL_OPTIONS.output_file);

   /* display the message */
   fprintf(stdout, " Writing output to \'%s\' ", GBL_OPTIONS.output_file);
   fflush(stdout);
   
   /* write the header */
   fh.magic = htons(EC_FILTER_MAGIC);
   strncpy(fh.version, EC_VERSION, sizeof(fh.version));
   
   write(fd, &fh, sizeof(struct filter_header));
   
   /* write the instructions */
   for (i = 0; i < ninst; i++) {
      print_progress_bar(&fop[i]);
      write(fd, &fop[i], sizeof(struct filter_op));
   }

   close(fd);
   
   fprintf(stdout, " done.\n\n");
  
   fprintf(stdout, " -> Script encoded into %d instructions.\n\n", i);
   
   return ESUCCESS;
}

/*
 * prints a differnt sign for every different instruction
 */
static void print_progress_bar(struct filter_op *fop)
{
   switch(fop->opcode) {
      case FOP_EXIT:
         ef_debug(1, "!");
         break;
      case FOP_TEST:
         ef_debug(1, "?");
         break;
      case FOP_ASSIGN:
         ef_debug(1, "=");
         break;
      case FOP_FUNC:
         ef_debug(1, ".");
         break;
      case FOP_JMP:
         ef_debug(1, ":");
         break;
      case FOP_JTRUE:
      case FOP_JFALSE:
         ef_debug(1, ";");
         break;
   }
}

/* EOF */

// vim:ts=3:expandtab

