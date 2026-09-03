/*
    etterfilter -- test module

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

*/

#include <ef.h>
#include <ec_filter.h>

#ifndef OS_WINDOWS
    #include <sys/mman.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

/* protos */

static char *escape_binary(const u_char *s, size_t len);

void test_filter(char *filename);

void print_fop(struct filter_op *fop, u_int32 eip);
static void print_test(struct filter_op *fop, u_int32 eip);
static void print_assign(struct filter_op *fop, u_int32 eip);
static void print_inc(struct filter_op *fop, u_int32 eip);
static void print_dec(struct filter_op *fop, u_int32 eip);
static void print_function(struct filter_op *fop, u_int32 eip);

/*******************************************/

/*
 * escape a binary string so it can be safely printed as a C-style string.
 * caller must SAFE_FREE the returned buffer.
 */
static char *escape_binary(const u_char *s, size_t len)
{
   char *out = NULL;
   size_t out_len = 0;
   size_t out_cap = 0;
   char hex[5];
   size_t i;

   if (s == NULL || len == 0) {
      SAFE_CALLOC(out, 1, sizeof(char));
      return out;
   }

   for (i = 0; i < len; i++) {
      u_char c = s[i];
      size_t needed;

      if (isprint((int)c) && c != '"' && c != '\\') {
         needed = 1;
      } else {
         needed = 4;  /* \\xNN */
      }

      if (out_len + needed + 1 > out_cap) {
         out_cap = out_cap ? out_cap * 2 : 16;
         if (out_cap < out_len + needed + 1)
            out_cap = out_len + needed + 1;
         SAFE_REALLOC(out, out_cap);
      }

      if (needed == 1) {
         out[out_len++] = (char)c;
      } else {
         snprintf(hex, sizeof(hex), "\\x%02x", c);
         memcpy(out + out_len, hex, 4);
         out_len += 4;
      }
   }

   out[out_len] = '\0';
   return out;
}


/*
 * test a binary filter against a given file 
 */
void test_filter(char *filename)
{
   struct filter_op *fop;
   struct filter_env *fenv;
   struct filter_list *flist;
   flist = NULL;
   u_int32 eip = 0;

   /*memset(fenv, 0, sizeof(struct filter_env));*/
   
   /* load the file */
   if (filter_load_file(filename, &flist, 1) != E_SUCCESS) {
      ef_exit(-1);
   }
   fenv = &flist->env;

   /* skip the header in the file */
   fop = fenv->chain;
   
   USER_MSG("Disassebling \"%s\" content...\n\n", filename);
  
   /* loop all the instructions and print their content */
   while (eip < (fenv->len / sizeof(struct filter_op)) ) {

      /* print the instruction */
      print_fop(&fop[eip], eip);
      
      /* autoincrement the instruction pointer */
      eip++;
   }

   USER_MSG("\n %d instructions decoded.\n\n", (int)(fenv->len / sizeof(struct filter_op)));

   ef_exit(0);
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
            
         case FOP_INC:
            print_inc(fop, eip);
            break;
            
         case FOP_DEC:
            print_dec(fop, eip);
            break;
            
         case FOP_FUNC:
            print_function(fop, eip);
            break;
            
         case FOP_JMP:
            USER_MSG("%04lu: JUMP ALWAYS to %04d\n", (unsigned long)eip, fop->op.jmp);
            break;
            
         case FOP_JTRUE:
            USER_MSG("%04lu: JUMP IF TRUE to %04d\n", (unsigned long)eip, fop->op.jmp);
            break;
            
         case FOP_JFALSE:
            USER_MSG("%04lu: JUMP IF FALSE to %04d\n", (unsigned long)eip, fop->op.jmp);
            break;
            
         case FOP_EXIT:
            USER_MSG("%04lu: EXIT\n", (unsigned long)eip);
            break;
            
         default:
            USER_MSG("UNDEFINED OPCODE (%d) !!\n", fop->opcode);
            ef_exit(-1);
            break;
      }
}

void print_test(struct filter_op *fop, u_int32 eip)
{
   char *escaped;

   switch(fop->op.test.op) {
      case FTEST_EQ:
         if (fop->op.test.size != 0)
            USER_MSG("%04lu: TEST level %d, offset %d, size %d, == %lu [%#x]\n", (unsigned long)eip,
               fop->op.test.level, fop->op.test.offset, fop->op.test.size, (unsigned long)fop->op.test.value, (unsigned int)fop->op.test.value);
         else {
            escaped = escape_binary(fop->op.test.string, fop->op.test.slen);
            USER_MSG("%04lu: TEST level %d, offset %d, \"%s\"\n", (unsigned long)eip,
               fop->op.test.level, fop->op.test.offset, escaped);
            SAFE_FREE(escaped);
         }
         break;
         
      case FTEST_NEQ:
         if (fop->op.test.size != 0)
            USER_MSG("%04lu: TEST level %d, offset %d, size %d, != %lu [%#x]\n", (unsigned long)eip,
               fop->op.test.level, fop->op.test.offset, fop->op.test.size, (unsigned long)fop->op.test.value, (unsigned int)fop->op.test.value);
         else {
            escaped = escape_binary(fop->op.test.string, fop->op.test.slen);
            USER_MSG("%04lu: TEST level %d, offset %d, not \"%s\"\n", (unsigned long)eip,
               fop->op.test.level, fop->op.test.offset, escaped);
            SAFE_FREE(escaped);
         }
         break;

      case FTEST_LT:
         USER_MSG("%04lu: TEST level %d, offset %d, size %d, < %lu [%#x]\n", (unsigned long)eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, (unsigned long)fop->op.test.value, (unsigned int)fop->op.test.value);
         break;
         
      case FTEST_GT:
         USER_MSG("%04lu: TEST level %d, offset %d, size %d, > %lu [%#x]\n", (unsigned long)eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, (unsigned long)fop->op.test.value, (unsigned int)fop->op.test.value);
         break;
         
      case FTEST_LEQ:
         USER_MSG("%04lu: TEST level %d, offset %d, size %d, <= %lu [%#x]\n", (unsigned long)eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, (unsigned long)fop->op.test.value, (unsigned int)fop->op.test.value);
         break;
         
      case FTEST_GEQ:
         USER_MSG("%04lu: TEST level %d, offset %d, size %d, >= %lu [%#x]\n", (unsigned long)eip,
            fop->op.test.level, fop->op.test.offset, fop->op.test.size, (unsigned long)fop->op.test.value, (unsigned int)fop->op.test.value);
         break;

      default:
         USER_MSG("%04lu: UNDEFINED TEST OPCODE (%d) !!\n", (unsigned long)eip, fop->op.test.op);
         break;
           
   }
}

void print_assign(struct filter_op *fop, u_int32 eip)
{
   char *escaped;

   if (fop->op.assign.size != 0)
      USER_MSG("%04lu: ASSIGNMENT level %d, offset %d, size %d, value %lu [%#x]\n", (unsigned long)eip,
            fop->op.assign.level, fop->op.assign.offset, fop->op.assign.size, (unsigned long)fop->op.assign.value, (unsigned int)fop->op.assign.value);
   else {
      escaped = escape_binary(fop->op.assign.string, fop->op.assign.slen);
      USER_MSG("%04lu: ASSIGNMENT level %d, offset %d, string \"%s\"\n", (unsigned long)eip,
            fop->op.assign.level, fop->op.assign.offset, escaped);
      SAFE_FREE(escaped);
   }
}

void print_inc(struct filter_op *fop, u_int32 eip)
{
      USER_MSG("%04lu: INCREMENT level %d, offset %d, size %d, value %lu [%#x]\n", (unsigned long)eip,
            fop->op.assign.level, fop->op.assign.offset, fop->op.assign.size, (unsigned long)fop->op.assign.value, (unsigned int)fop->op.assign.value);
}

void print_dec(struct filter_op *fop, u_int32 eip)
{
      USER_MSG("%04lu: DECREMENT level %d, offset %d, size %d, value %lu [%#x]\n", (unsigned long)eip,
            fop->op.assign.level, fop->op.assign.offset, fop->op.assign.size, (unsigned long)fop->op.assign.value, (unsigned int)fop->op.assign.value);
}

void print_function(struct filter_op *fop, u_int32 eip)
{
   char *escaped;
   char *replaced;

   switch (fop->op.func.op) {
      case FFUNC_SEARCH:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: SEARCH level %d, string \"%s\"\n", (unsigned long)eip,
               fop->op.func.level, escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_REGEX:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: REGEX level %d, string \"%s\"\n", (unsigned long)eip,
               fop->op.func.level, escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_PCRE:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         if (fop->op.func.replace) {
            replaced = escape_binary(fop->op.func.replace, fop->op.func.rlen);
            USER_MSG("%04lu: PCRE_REGEX level %d, string \"%s\", replace \"%s\"\n", (unsigned long)eip,
                  fop->op.func.level, escaped, replaced);
            SAFE_FREE(replaced);
         } else
            USER_MSG("%04lu: PCRE_REGEX level %d, string \"%s\"\n", (unsigned long)eip,
                  fop->op.func.level, escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_REPLACE:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         replaced = escape_binary(fop->op.func.replace, fop->op.func.rlen);
         USER_MSG("%04lu: REPLACE \"%s\" --> \"%s\"\n", (unsigned long)eip,
               escaped, replaced);
         SAFE_FREE(escaped);
         SAFE_FREE(replaced);
         break;

      case FFUNC_INJECT:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: INJECT \"%s\"\n", (unsigned long)eip,
               escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_EXECINJECT:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: EXECINJECT \"%s\"\n", (unsigned long)eip,
               escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_RANDOM:
         USER_MSG("%04lu: RANDOM level %d start offset %d length %d\n", (unsigned long)eip,
               fop->op.func.level, fop->op.func.offset, fop->op.func.olen);
         break;

      case FFUNC_LOG:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: LOG to \"%s\"\n", (unsigned long)eip, escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_DROP:
         USER_MSG("%04lu: DROP\n", (unsigned long)eip);
         break;

      case FFUNC_KILL:
         USER_MSG("%04lu: KILL\n", (unsigned long)eip);
         break;

      case FFUNC_MSG:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: MSG \"%s\"\n", (unsigned long)eip, escaped);
         SAFE_FREE(escaped);
         break;

      case FFUNC_EXEC:
         escaped = escape_binary(fop->op.func.string, fop->op.func.slen);
         USER_MSG("%04lu: EXEC \"%s\"\n", (unsigned long)eip, escaped);
         SAFE_FREE(escaped);
         break;

      default:
         USER_MSG("%04lu: UNDEFINED FUNCTION OPCODE (%d)!!\n", (unsigned long)eip, fop->op.func.op);
         break;
   }

}


/* EOF */

// vim:ts=3:expandtab

