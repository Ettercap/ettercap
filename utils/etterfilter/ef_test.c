/*
    etterfilter -- test module

    Copyright (C) ALoR & NaGA

    This program is free software; you can redfopibute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is dfopibuted in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id: ef_test.c,v 1.12 2003/09/30 18:04:03 alor Exp $
*/

#include <ef.h>
#include <ec_filter.h>
#include <ec_version.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* protos */

void test_filter(char *filename);

void print_fop(struct filter_op *fop, u_int32 eip);
static void print_test(struct filter_op *fop, u_int32 eip);
static void print_assign(struct filter_op *fop, u_int32 eip);
static void print_function(struct filter_op *fop, u_int32 eip);

/*******************************************/

/*
 * test a binary filter against a given file 
 */
void test_filter(char *filename)
{
   int fd;
   struct filter_header fh;
   struct filter_op *fop;
   u_int32 eip = 0;
   size_t size = 7;

   /* open the file */
   if ((fd = open(filename, O_RDONLY)) == -1)
      FATAL_ERROR("File not found or permission denied");

   /* read the header */
   if (read(fd, &fh, sizeof(struct filter_header)) != sizeof(struct filter_header))
      FATAL_ERROR("The file is corrupted");

   /* sanity checks */
   if (fh.magic != htons(EC_FILTER_MAGIC))
      FATAL_ERROR("Bad magic in filter file");
  
   /* which version has compiled the filter ? */
   if (strcmp(fh.version, EC_VERSION))
      FATAL_ERROR("Filter compiled for a different version");
   
   /* get the size */
   size = lseek(fd, 0, SEEK_END) - sizeof(struct filter_header);

   /* size must be a multiple of filter_op */
   if ((size % sizeof(struct filter_op) != 0) || size == 0)
      FATAL_ERROR("The file contains invalid instructions");
   
   /* 
    * load the file in memory 
    * skipping the initial header
    */
   fop = (struct filter_op *) mmap(NULL, size + sizeof(struct filter_header), PROT_READ, MAP_PRIVATE, fd, 0);
   if (fop == MAP_FAILED)
      FATAL_ERROR("Cannot mmap file");

   /* the mmap will remain active even if we close the fd */
   close(fd);

   /* skip the header in the file */
   fop = (struct filter_op *)((char *)fop + sizeof(struct filter_header));
   
   fprintf(stdout, "Debugging \"%s\" content...\n\n", filename);
  
   /* loop all the instructions and print their content */
   while (eip < (size / sizeof(struct filter_op)) ) {

      /* print the instruction */
      print_fop(&fop[eip], eip);
      
      /* autoincrement the instruction pointer */
      eip++;
   }

   printf("\n");

   exit(0);
}

/*
 * helper functions to print instructions
 */
void print_fop(struct filter_op *fop, u_int32 eip)
{
      switch (fop->opcode) {
         case FOP_TEST:
            print_test(fop, eip);
            break;
            
         case FOP_ASSIGN:
            print_assign(fop, eip);
            break;
            
         case FOP_FUNC:
            print_function(fop, eip);
            break;
            
         case FOP_JMP:
            fprintf(stdout, "%04d: JUMP ALWAYS to %04d\n", eip, fop->op.jmp);
            break;
            
         case FOP_JTRUE:
            fprintf(stdout, "%04d: JUMP IF TRUE to %04d\n", eip, fop->op.jmp);
            break;
            
         case FOP_JFALSE:
            fprintf(stdout, "%04d: JUMP IF FALSE to %04d\n", eip, fop->op.jmp);
            break;
            
         case FOP_EXIT:
            fprintf(stdout, "%04d: EXIT\n", eip);
            break;
            
         default:
            fprintf(stderr, "UNDEFINED OPCODE (%d) !!\n", fop->opcode);
            exit(-1);
            break;
      }
}

void print_test(struct filter_op *fop, u_int32 eip)
{
   switch(fop->op.test.op) {
      case FTEST_EQ:
         if (fop->op.test.size != 0)
            fprintf(stdout, "%04d: TEST level %d, offset %d, size %d, == %d\n", eip,
               fop->op.test.level, fop->op.test.offset, fop->op.test.size, fop->op.test.value);
         else
            fprintf(stdout, "%04d: TEST level %d, offset %d, \"%s\"\n", eip,
               fop->op.test.level, fop->op.test.offset, fop->op.test.string);
         break;
         
      case FTEST_NEQ:
         if (fop->op.test.size != 0)
            fprintf(stdout, "%04d: TEST level %d, offset %d, size %d, != %d\n", eip,
               fop->op.test.level, fop->op.test.offset, fop->op.test.size, fop->op.test.value);
         else
            fprintf(stdout, "%04d: TEST level %d, offset %d, not \"%s\"\n", eip,
               fop->op.test.level, fop->op.test.offset, fop->op.test.string);
         break;

      case FTEST_LT:
         fprintf(stdout, "%04d: TEST level %d, offset %d, size %d, < %d\n", eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, fop->op.test.value);
         break;
         
      case FTEST_GT:
         fprintf(stdout, "%04d: TEST level %d, offset %d, size %d, > %d\n", eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, fop->op.test.value);
         break;
         
      case FTEST_LEQ:
         fprintf(stdout, "%04d: TEST level %d, offset %d, size %d, <= %d\n", eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, fop->op.test.value);
         break;
         
      case FTEST_GEQ:
         fprintf(stdout, "%04d: TEST level %d, offset %d, size %d, >= %d\n", eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, fop->op.test.value);
         break;

      default:
         fprintf(stderr, "%04d: UNDEFINED TEST OPCODE (%d) !!", eip, fop->op.test.op);
         break;
           
   }
}

void print_assign(struct filter_op *fop, u_int32 eip)
{
   if (fop->op.assign.size != 0)
      fprintf(stdout, "%04d: ASSIGNMENT level %d, offset %d, size %d, value %d\n", eip,
            fop->op.assign.level, fop->op.assign.offset, fop->op.assign.size, fop->op.assign.value);
   else
      fprintf(stdout, "%04d: ASSIGNMENT level %d, offset %d, string \"%s\"\n", eip, 
            fop->op.assign.level, fop->op.assign.offset, fop->op.assign.string);
      
}

void print_function(struct filter_op *fop, u_int32 eip)
{
   switch (fop->op.func.op) {
      case FFUNC_SEARCH:
         fprintf(stdout, "%04d: SEARCH level %d, string \"%s\"\n", eip, 
               fop->op.func.level, fop->op.func.value);
         break;
         
      case FFUNC_REGEX:
         fprintf(stdout, "%04d: REGEX level %d, string \"%s\"\n", eip, 
               fop->op.func.level, fop->op.func.value);
         break;

      case FFUNC_REPLACE:
         fprintf(stdout, "%04d: REPLACE \"%s\" --> \"%s\"\n", eip, 
               fop->op.func.value, fop->op.func.value2);
         break;
         
      case FFUNC_INJECT:
         fprintf(stdout, "%04d: INJECT \"%s\"\n", eip, 
               fop->op.func.value);
         break;
         
      case FFUNC_LOG:
         fprintf(stdout, "%04d: LOG to \"%s\"\n", eip, fop->op.func.value);
         break;
         
      case FFUNC_DROP:
         fprintf(stdout, "%04d: DROP\n", eip);
         break;
         
      case FFUNC_MSG:
         fprintf(stdout, "%04d: MSG \"%s\"\n", eip, fop->op.func.value);
         break;
         
      case FFUNC_EXEC:
         fprintf(stdout, "%04d: EXEC \"%s\"\n", eip, fop->op.func.value);
         break;
         
      default:
         fprintf(stderr, "%04d: UNDEFINED TEST OPCODE (%d)!!", eip, fop->op.func.op);
         break;
   }

}


/* EOF */

// vim:ts=3:expandtab

