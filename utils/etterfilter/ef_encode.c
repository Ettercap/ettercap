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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_encode.c,v 1.1 2003/09/10 21:10:37 alor Exp $
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

/*******************************************/

/*
 * search an offset and fill the filter_op structure
 * return ESUCCESS on error.
 */
int encode_offset(char *string, struct filter_op *fop)
{
   return ESUCCESS;
}


/*
 * parse a function and its arguments and fill the structure
 */
int encode_function(char *string, struct filter_op *fop)
{
   return ESUCCESS;
}


/*
 * assing the value of the const to the fop.value
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
  
      /* remove the quotes */
      p = strchr(string + 1, '\"');
      *p = '\0';
      /* copy it */
      strlcpy(fop->op.test.string, string + 1, MAX_FILTER_LEN);
     
      return ESUCCESS;
      
   /* it is a constant */
   } else if (isalpha((int)string[0])) {
      return get_constant(string, &fop->op.test.value);
   }
   
   /* anything else is an error */
   return -ENOTFOUND;
}


/* EOF */

// vim:ts=3:expandtab

