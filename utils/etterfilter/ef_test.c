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

    $Id: ef_test.c,v 1.7 2003/09/19 16:47:51 alor Exp $
*/

#include <ef.h>
#include <ec_filter.h>

/* protos */

void test_filter(char *filename);

void print_test(struct filter_op *fop, u_int32 eip);
void print_assign(struct filter_op *fop, u_int32 eip);
void print_function(struct filter_op *fop, u_int32 eip);

/*******************************************/

/*
 * test a binary filter against a given file 
 */
void test_filter(char *filename)
{
   struct filter_op *fop;
   u_int32 eip = 0;
   size_t size = 7;

   NOT_IMPLEMENTED();
   
   fop = calloc(size, sizeof(struct filter_op));
   
   /* if (DATA.data, search("OpenSSH")) { */
   fop[0].opcode = FOP_FUNC;
   fop[0].op.func.op = FFUNC_SEARCH;
   fop[0].op.func.level = 5;
   strcpy(fop[0].op.func.value, "OpenSSH");
   fop[0].op.func.value_len = strlen(fop[0].op.func.value);
   
   fop[1].opcode = FOP_JFALSE;
   fop[1].op.jmp = 5;

   /* replace("SSH-1.99", "SSH-1.51"); */
   fop[2].opcode = FOP_FUNC;
   fop[2].op.func.op = FFUNC_REPLACE;
   fop[2].op.func.level = 5;
   strcpy(fop[2].op.func.value, "SSH-1.99");
   fop[2].op.func.value_len = strlen(fop[2].op.func.value);
   strcpy(fop[2].op.func.value2, "SSH-1.51");
   fop[2].op.func.value2_len = strlen(fop[2].op.func.value2);
  
   /* msg("SSH downgraded to version 1"); */
   fop[3].opcode = FOP_FUNC;
   fop[3].op.func.op = FFUNC_MSG;
   strcpy(fop[3].op.func.value, "SSH downgraded to version 1");
   
   fop[4].opcode = FOP_JMP;
   fop[4].op.jmp = 6;
   
   /* } else { DATA.data + 3 = '+' */
   fop[5].opcode = FOP_ASSIGN;
   fop[5].op.assign.level = 5;
   fop[5].op.assign.offset = 3;
   fop[5].op.assign.size = 1;
   fop[5].op.assign.value = '+';

   /* } */
   fop[6].opcode = FOP_EXIT;
 
   fprintf(stdout, "Debugging \"%s\" content...\n\n", filename);
  
   /* loop all the instructions and print their content */
   while (eip < size) {

      switch (fop[eip].opcode) {
         case FOP_TEST:
            print_test(&fop[eip], eip);
            break;
            
         case FOP_ASSIGN:
            print_assign(&fop[eip], eip);
            break;
            
         case FOP_FUNC:
            print_function(&fop[eip], eip);
            break;
            
         case FOP_JMP:
            fprintf(stdout, "%04d: JUMP ALWAYS to %04d\n", eip, fop[eip].op.jmp);
            break;
            
         case FOP_JTRUE:
            fprintf(stdout, "%04d: JUMP IF TRUE to %04d\n", eip, fop[eip].op.jmp);
            break;
            
         case FOP_JFALSE:
            fprintf(stdout, "%04d: JUMP IF FALSE to %04d\n", eip, fop[eip].op.jmp);
            break;
            
         case FOP_EXIT:
            fprintf(stdout, "%04d: EXIT\n", eip);
            break;
            
         default:
            fprintf(stderr, "UNDEFINED OPCODE (%d) !!\n", fop[eip].opcode);
            exit(-1);
            break;
      }
    
      /* autoincrement the instruction pointer */
      eip++;
   }

   printf("\n");

   exit(0);
}

/*
 * helper functions to print instructions
 */

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

