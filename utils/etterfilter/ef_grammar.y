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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_grammar.y,v 1.1 2003/08/28 19:55:20 alor Exp $
*/

%{

#include <ef.h>
#include <ef_functions.h>

#define YYERROR_VERBOSE

int lineno = 1;
 
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
      | input line
      ;
     
/* we can have lines containing ACTIONS or EXPRESSIONS */
line: TOKEN_EOL { lineno++; }
      | TOKEN_IF TOKEN_PAR_OPEN instruction TOKEN_PAR_CLOSE TOKEN_BLK_BEGIN TOKEN_EOL 
      { 
         lineno++;
      }
      | TOKEN_BLK_END TOKEN_ELSE TOKEN_BLK_BEGIN TOKEN_EOL 
      { 
         lineno++;
      }
      | TOKEN_BLK_END TOKEN_EOL 
      { 
         lineno++;
      }
      | instruction TOKEN_OP_END TOKEN_EOL 
      { 
         lineno++;
      }
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

num: math_expr {}
      | TOKEN_OFFSET {}
      ;

instruction: TOKEN_FUNCTION {}
      | TOKEN_OFFSET TOKEN_OP_CMP num {}
      | TOKEN_OFFSET TOKEN_OP_EQ num {}
      | TOKEN_OP_NOT instruction {}
      ;

%%

/* 
 * ==========================================
 *                C Code  
 * ==========================================
 */

/*
 * This function is needed by bison. so it MUST exist.
 * It is the error handler.
*/

int yyerror(char *s)  
{ 
   fprintf (stderr, "[%s:%d]: ERROR: %s\n", GBL_OPTIONS.source_file, lineno, s); 
   return 1;
}
                           
