/*
    etterfilter -- syntax for filter source files

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_syntax.l,v 1.1 2003/08/28 19:55:20 alor Exp $
*/

%{

#include <ef.h>
#include <ef_functions.h>

#include <ef_grammar.h>

#define YY_NO_UNPUT

%}

/* 
 * ==========================================
 *          FLEX Declarations 
 * ==========================================
 */
 
%option  noyywrap

OFFSET         [A-Za-z]+[[:alnum:]]+[\.[A-Za-z]+]*
FUNCTION       [A-Za-z]+\([^\)]*\)
CONST          [0-9]+
SPACES         [ \t]+

%%

"if" {
   printf("IF\n");
   return TOKEN_IF;
}

"else" {
   printf("ELSE\n");
   return TOKEN_ELSE;
}

"!" {
   printf("NOT");
   return TOKEN_OP_NOT;
}

"==" {
   printf("CMP\n");
   return TOKEN_OP_CMP;
}

"=" {
   printf("EQ\n");
   return TOKEN_OP_EQ;
}

"*" {
   return TOKEN_OP_MUL;
}

"+" {
   return TOKEN_OP_ADD;
}

"-" {
   return TOKEN_OP_SUB;
}

"/" {
   return TOKEN_OP_DIV;
}

"(" {
   printf("(\n");
   return TOKEN_PAR_OPEN;
}

")" {
   printf(")\n");
   return TOKEN_PAR_CLOSE;
}

"{" {
   printf("{\n");
   return TOKEN_BLK_BEGIN;
}

"}" {
   printf("}\n");
   return TOKEN_BLK_END;
}

";" {
   printf("}\n");
   return TOKEN_OP_END;
}

{OFFSET} {
   printf("OFFSET: %s\n", yytext);
   yylval.string = strdup(yytext);
   return TOKEN_OFFSET;
}

{FUNCTION} {
   printf("FUNCTION: %s\n", yytext);
   yylval.string = strdup(yytext);
   return TOKEN_FUNCTION;
}

{CONST} {
   printf("CONST: %s\n", yytext);
   yylval.value = atoi(yytext);
   return TOKEN_CONST;
}

{SPACES}       /* eat up the blank space */

"/*".*"*/"     /* eat up one line comments */
"#".*

[\n\r] {
   return TOKEN_EOL;
}

. /* ignore unrecognized character; the parser will report the error */

%%

/* 
 * ==========================================
 *                C Code  
 * ==========================================
 */

