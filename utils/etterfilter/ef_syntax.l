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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_syntax.l,v 1.8 2003/09/13 10:04:15 alor Exp $
*/

%{

#include <ef.h>
#include <ef_functions.h>
#include <ec_filter.h>
/* from bison */
#include <ef_grammar.h>

#define YY_NO_UNPUT

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
STRING         \"[[:graph:]]*\"
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
   printf(";\n");
   return TOKEN_OP_END;
}

{OFFSET} {
   printf("OFFSET: %s\n", yytext);
   
   if (encode_offset(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Offset \"%s\" not recognized", yytext);
   
   return TOKEN_OFFSET;
}

{FUNCTION} {
   printf("FUNCTION: %s\n", yytext);
   
   if (encode_function(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Function \"%s\" not recognized", yytext);
   
   return TOKEN_FUNCTION;
}

{CONST} {
   printf("CONST: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Constant \"%s\" not recognized", yytext);
   
   return TOKEN_CONST;
}

{STRING} {
   printf("STRING: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Invalid string [%s]", yytext);
   
   return TOKEN_STRING;
}

{SPACES}       /* eat up the blank spaces */

"/*".*"*/"     /* eat up one line comments */
"#".*

[\n\r] {
   /* increment the line number (used for error reporting) */
   GBL.lineno++;
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

