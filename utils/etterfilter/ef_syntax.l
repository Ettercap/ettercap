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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_syntax.l,v 1.5 2003/09/10 15:41:23 alor Exp $
*/

%{

#include <ef.h>
#include <ef_functions.h>
#include <ef_grammar.h>

#define YY_NO_UNPUT

/* declared in ef_grammar.y */
extern u_int32 lineno;

%}

/* 
 * ==========================================
 *          FLEX Declarations 
 * ==========================================
 */
 
%option  noyywrap

OFFSET         [[:alnum:]]+\.[A-Za-z]+[\.[A-Za-z]+]*
FUNCTION       [A-Za-z]+\([^\)]*\)
CONST          [0-9]+|0x[0-9]+|[A-Z]+
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
   printf("NOT\n");
   return TOKEN_OP_NOT;
}

"&&" {
   printf("AND\n");
   return TOKEN_OP_AND;
}

"||" {
   printf("OR\n");
   return TOKEN_OP_OR;
}

"==" {
   printf("CMP EQ\n");
   return TOKEN_OP_CMP_EQ;
}

"<" {
   printf("CMP LT\n");
   return TOKEN_OP_CMP_LT;
}

">" {
   printf("CMP GT\n");
   return TOKEN_OP_CMP_GT;
}

"<=" {
   printf("CMP LEQ\n");
   return TOKEN_OP_CMP_LEQ;
}

">=" {
   printf("CMP GEQ\n");
   return TOKEN_OP_CMP_GEQ;
}

"=" {
   printf("ASSIGN\n");
   return TOKEN_OP_ASSIGN;
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
   if (!strncmp(yytext, "0x", 2))
      yylval.value = strtoul(yytext, NULL, 16);
   else
      yylval.value = strtoul(yytext, NULL, 10);
   return TOKEN_CONST;
}

{SPACES}       /* eat up the blank space */

"/*".*"*/"     /* eat up one line comments */
"#".*

[\n\r] {
   lineno++;
   //return TOKEN_EOL;
}

. {
   yylval.string = strdup(yytext);
   return TOKEN_UNKNOWN;
}

%%

/* 
 * ==========================================
 *                C Code  
 * ==========================================
 */

/* EOF */

// vim:ts=3:expandtab

