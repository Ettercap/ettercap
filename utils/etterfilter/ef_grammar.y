/*
    etterfilter -- grammar for filter source files

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_grammar.y,v 1.2 2003/09/02 21:11:09 alor Exp $
*/

%{

#include <ef.h>
#include <ef_functions.h>
#include <ec_strings.h>

#define YYERROR_VERBOSE

u_int32 lineno = 1;
 
%}
 
/* 
 * ==========================================
 *          BISON Declarations 
 * ==========================================
 */
 
/* definition for the yylval (global variable) */
%union {
   int value;        /* semantic value for integer variables or numbers */
   char *string;     /* a string identifying the name of a variable */
}

/* token definitions */
%token TOKEN_EOL

%token <value>  TOKEN_CONST     /* an integer number */
%token <string> TOKEN_OFFSET    /* an offset in the form xxxx.yyy.zzzzz */
%token <string> TOKEN_FUNCTION  /* a function */

%token TOKEN_IF          /*  if ( ) {  */
%token TOKEN_ELSE        /*  } else {  */

%token TOKEN_OP_NOT      /*  !  */

%token TOKEN_OP_EQ       /*  =  */
%token TOKEN_OP_CMP      /*  ==  */

%token TOKEN_OP_END      /*  ;  */

%token TOKEN_PAR_OPEN    /*  (  */
%token TOKEN_PAR_CLOSE   /*  )  */

%token TOKEN_BLK_BEGIN   /*  {  */
%token TOKEN_BLK_END     /*  }  */

%token TOKEN_UNKNOWN

/* non terminals */
%type <value> math_expr

/* precedences */
%left TOKEN_OP_SUB TOKEN_OP_ADD
%left TOKEN_OP_MUL TOKEN_OP_DIV
%left TOKEN_UMINUS /* unary minus */

%%

/* 
 * ==========================================
 *          GRAMMAR Definitions 
 * ==========================================
*/

/* general line, can be empty or not */ 
input: /* empty string */
      | input block
      ;
     
block: TOKEN_EOL {  }
      | if_statement { } 
      | if_else_statement { }
      | single_instruction { }
      ;
      
if_statement: TOKEN_IF TOKEN_PAR_OPEN instruction TOKEN_PAR_CLOSE TOKEN_BLK_BEGIN block TOKEN_BLK_END 
      {
         printf("\tONLY IF\n");
      }
      ;
      
if_else_statement: TOKEN_IF TOKEN_PAR_OPEN instruction TOKEN_PAR_CLOSE TOKEN_BLK_BEGIN block TOKEN_BLK_END TOKEN_ELSE TOKEN_BLK_BEGIN block TOKEN_BLK_END
      { 
         printf("\tIF ELSE\n");
      }
      ;

single_instruction: instruction TOKEN_OP_END
      { 
      }
      ;

instruction: TOKEN_FUNCTION {}
      | TOKEN_OFFSET TOKEN_OP_CMP num {}
      | TOKEN_OFFSET TOKEN_OP_EQ num {}
      | TOKEN_OP_NOT instruction {}
      ;
      
num: math_expr {}
      | TOKEN_OFFSET {}
      ;
      
/* MATH EXPRESSION definition */
math_expr: TOKEN_CONST  { $$ = $1; }
      | math_expr TOKEN_OP_ADD math_expr { $$ = $1 + $3; }
      | math_expr TOKEN_OP_SUB math_expr { $$ = $1 - $3; }
      | math_expr TOKEN_OP_MUL math_expr { $$ = $1 * $3; }
      | math_expr TOKEN_OP_DIV math_expr { $$ = $1 / $3; }
      | TOKEN_OP_SUB math_expr %prec TOKEN_UMINUS { $$ = -$2; }
      | TOKEN_PAR_OPEN math_expr TOKEN_PAR_CLOSE { $$ = $2; }
      ;

%%

/* 
 * ==========================================
 *                C Code  
 * ==========================================
 */

/*
 * name of the token as they should be presented to the user
 */
struct {
   char *name;
   char *string;
} errors_array[] = 
   {
      { "TOKEN_CONST", "an integer" },
      { "TOKEN_OFFSET", "an offset" },
      { "TOKEN_FUNCTION", "a function" },
      { "TOKEN_IF", "'if'" },
      { "TOKEN_ELSE", "'else'" },
      { "TOKEN_OP_NOT", "'!'" },
      { "TOKEN_OP_EQ", "'='" },
      { "TOKEN_OP_CMP", "'=='" },
      { "TOKEN_OP_END", "';'" },
      { "TOKEN_PAR_OPEN", "'('" },
      { "TOKEN_PAR_CLOSE", "')'" },
      { "TOKEN_BLK_BEGIN", "'{'" },
      { "TOKEN_BLK_END", "'}'" },
      { NULL, NULL }
   };

/*
 * This function is needed by bison. so it MUST exist.
 * It is the error handler.
 */
int yyerror(char *s)  
{ 
   char *error;
   int i = 0;

   /* make a copy to manipulate it */
   error = strdup(s);
  
   /* subsitute the error code with frendly messages */
   do {
      str_replace(&error, errors_array[i].name, errors_array[i].string);
   } while(errors_array[++i].name != NULL);

   /* special case for UNKNOWN */
   if (strstr(error, "TOKEN_UNKNOWN"))
      str_replace(&error, "TOKEN_UNKNOWN", yylval.string);
 
   /* print the actual error message */
   fprintf (stderr, "[%s:%d]: %s\n", GBL_OPTIONS.source_file, lineno, error);

   SAFE_FREE(error);

   /* return the error */
   return 1;
}

/* EOF */

// vim:ts=3:expandtab

