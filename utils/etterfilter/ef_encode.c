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

    $Id: ef_encode.c,v 1.9 2003/09/27 17:22:24 alor Exp $
*/

#include <ef.h>
#include <ef_functions.h>
#include <ec_filter.h>
#include <ec_strings.h>

#include <ctype.h>

/* protos */

int encode_offset(char *string, struct filter_op *fop);
int encode_function(char *string, struct filter_op *fop);
int encode_const(char *string, struct filter_op *fop);
static char ** decode_args(char *args, int *nargs);

/*******************************************/

/*
 * search an offset and fill the filter_op structure
 * return ESUCCESS on error.
 */
int encode_offset(char *string, struct filter_op *fop)
{
   char *str, *p, *q;
   int ret;

   /* make the modifications on a copy */
   str = strdup(string);
   
   /*
    * the offset contains at least one '.'
    * we are sure because the syntax parser
    * will not have passed it here if it is not
    * in the right form.
    */
   p = strtok(str, ".");
   q = strtok(NULL, ".");

   /* the the virtual pointer from the table */
   ret = get_virtualpointer(p, q, &fop->op.test.level, &fop->op.test.offset, &fop->op.test.size);

   SAFE_FREE(str);

   return ret;
}


/*
 * assing the value of the const to the fop.value
 *
 * all the value are integer32 and are saved in host order
 */
int encode_const(char *string, struct filter_op *fop)
{
   char *p;
   
   /* it is an hexadecimal value */
   if (!strncmp(string, "0x", 2) && isdigit((int)string[2])) {
      fop->op.test.value = strtoul(string, NULL, 16);
      return ESUCCESS;
      
   /* it is an integer value */
   } else if (isdigit((int)string[0])) {
      fop->op.test.value = strtoul(string, NULL, 10);
      return ESUCCESS;
      
   /* it is a string */
   } else if (string[0] == '\"' && string[strlen(string) - 1] == '\"') {
  
      /* check if the string is short enough */
      if (strlen(string) > MAX_FILTER_LEN)
         SCRIPT_ERROR("String too long. (max %d char)", MAX_FILTER_LEN)
            
      /* remove the quotes */
      p = strchr(string + 1, '\"');
      *p = '\0';

      /* escape it in the structure */
      fop->op.test.string_len = strescape(fop->op.test.string, string);
     
      return ESUCCESS;
      
   /* it is a constant */
   } else if (isalpha((int)string[0])) {
      return get_constant(string, &fop->op.test.value);
   }
   
   /* anything else is an error */
   return -ENOTFOUND;
}


/*
 * parse a function and its arguments and fill the structure
 */
int encode_function(char *string, struct filter_op *fop)
{
   char *str = strdup(string);
   int ret = -ENOTFOUND;
   char *name, *args;
   int nargs = 0, i;
   char **dec_args = NULL;

   /* get the name of the function */
   name = strtok(string, "(");
   /* get all the args */
   args = strtok(NULL, "(");

   /* analyze the arguments */
   dec_args = decode_args(args, &nargs);

   /* this fop is a function */
   fop->opcode = FOP_FUNC;

   /* check if it is a known function */
   if (!strcmp(name, "search")) {
      if (nargs == 2) {
         /* get the level (DATA or DECODED) */
         if (encode_offset(dec_args[0], fop) == ESUCCESS) {
            fop->op.func.op = FFUNC_SEARCH;
            fop->op.func.value_len = strescape(fop->op.func.value, dec_args[1]);
            ret = ESUCCESS;
         }
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "regex")) {
      if (nargs == 2) {
         /* get the level (DATA or DECODED) */
         if (encode_offset(dec_args[0], fop) == ESUCCESS) {
            fop->op.func.op = FFUNC_REGEX;
            fop->op.func.value_len = strescape(fop->op.func.value, dec_args[1]);
            ret = ESUCCESS;
         }
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "replace")) {
      if (nargs == 2) {
         fop->op.func.op = FFUNC_REPLACE;
         /* replace always operate at DATA level */
         fop->op.func.level = 5;
         fop->op.func.value_len = strescape(fop->op.func.value, dec_args[0]);
         fop->op.func.value2_len = strescape(fop->op.func.value2, dec_args[1]);
         ret = ESUCCESS;
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "inject")) {
      if (nargs == 1) {
         fop->op.func.op = FFUNC_INJECT;
         /* inject always operate at DATA level */
         fop->op.func.level = 5;
         strncpy(fop->op.func.value, dec_args[0], MAX_FILTER_LEN);
         ret = ESUCCESS;
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "log")) {
      if (nargs == 2) {
         /* get the level (DATA or DECODED) */
         if (encode_offset(dec_args[0], fop) == ESUCCESS) {
            fop->op.func.op = FFUNC_LOG;
            strncpy(fop->op.func.value, dec_args[1], MAX_FILTER_LEN);
            ret = ESUCCESS;
         }
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "drop")) {
      if (nargs == 0) {
         fop->op.func.op = FFUNC_DROP;
         ret = ESUCCESS;
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "msg")) {
      if (nargs == 1) {
         fop->op.func.op = FFUNC_MSG;
         strncpy(fop->op.func.value, dec_args[0], MAX_FILTER_LEN);
         fop->op.func.value_len = strlen(dec_args[0]);
         ret = ESUCCESS;
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "exec")) {
      if (nargs == 1) {
         fop->op.func.op = FFUNC_EXEC;
         strncpy(fop->op.func.value, dec_args[0], MAX_FILTER_LEN);
         fop->op.func.value_len = strlen(dec_args[0]);
         ret = ESUCCESS;
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   } else if (!strcmp(name, "exit")) {
      if (nargs == 0) {
         fop->opcode = FOP_EXIT;
         ret = ESUCCESS;
      } else
         SCRIPT_ERROR("Wrong number of arguments for function \"%s\" ", name);
   }

   /* free the array */
   for (i = 0; i < nargs; i++)
      SAFE_FREE(dec_args[i]);
      
   SAFE_FREE(dec_args);
   SAFE_FREE(str);
   return ret;
}

/*
 * split the args of a function and return
 * the number of found args
 */
static char ** decode_args(char *args, int *nargs)
{
   char *p, *q, *arg;
   int i = 0;
   char **parsed;

   *nargs = 0;
  
   /* get the end */
   p = strchr(args, ')');
   *p = '\0';
   
   /* trim the empty spaces */
   for (; *args == ' '; args++);
   for (q = args + strlen(args) - 1; *q == ' '; q--)
      *q = '\0';

   /* there are no arguments */
   if (!strchr(args, ',') && strlen(args) == 0)
      return NULL;
  
   SAFE_CALLOC(parsed, 1, sizeof(char *));
   
   /* split the arguments */
   for (p = strsep(&args, ","), i = 1; p != NULL; p = strsep(&args, ","), i++) {
      
      /* alloc the array for the arguments */
      parsed = (char **)realloc(parsed, (i+1) * sizeof(char *));
      ON_ERROR(parsed, NULL, "virtual memory exhausted");
      
      /* trim the empty spaces */
      for (arg = p; *arg == ' '; arg++);
      for (q = arg + strlen(arg) - 1; *q == ' '; q--)
         *q = '\0';
    
      /* check if the string is short enough */
      if (strlen(arg) > MAX_FILTER_LEN)
         SCRIPT_ERROR("String too long. (max %d char)", MAX_FILTER_LEN)
            
      /* put in in the array */
      parsed[i - 1] = strdup(arg);
   }

   /* return the number of args */
   *nargs = i - 1;
   
   return parsed;
}

/* EOF */

// vim:ts=3:expandtab

