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

*/

%{

#include <ef.h>
#include <ef_functions.h>
#include <ec_filter.h>
/* from bison */
#include <ef_grammar.h>


%}

/* 
 * ==========================================
 *          FLEX Declarations 
 * ==========================================
 */
 
%option  noyywrap
%option  nounput
%option  noinput

OFFSET         [[:alnum:]]+\.[A-Za-z]+[\.[A-Za-z]+]*
FUNCTION       [a-z_]+\((.*\".*\"[^)]*)*\)
CONST          [0-9]+|0x[0-9a-fA-F]+|[A-Z6]+
STRING         \"([^\0"\\]*(\\.[^\0"\\]*)*)\"
IPADDR         \'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\'
IP6ADDR        \'[0-9a-fA-F]{4}[0-9a-fA-F:]+:[0-9a-fA-F]{1,4}\'|\'::1\'
SPACES         [ \t]+

%%

"if" {
   ef_debug(5, "IF\n");
   return TOKEN_IF;
}

"else" {
   ef_debug(5, "ELSE\n");
   return TOKEN_ELSE;
}

"&&" {
   return TOKEN_OP_AND;
}

"||" {
   return TOKEN_OP_OR;
}

"!=" {
   return TOKEN_OP_CMP_NEQ;
}

"==" {
   return TOKEN_OP_CMP_EQ;
}

"<" {
   return TOKEN_OP_CMP_LT;
}

">" {
   return TOKEN_OP_CMP_GT;
}

"<=" {
   return TOKEN_OP_CMP_LEQ;
}

">=" {
   return TOKEN_OP_CMP_GEQ;
}

"=" {
   return TOKEN_OP_ASSIGN;
}

"+=" {
   return TOKEN_OP_INC;
}

"-=" {
   return TOKEN_OP_DEC;
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
   return TOKEN_PAR_OPEN;
}

")" {
   return TOKEN_PAR_CLOSE;
}

"{" {
   return TOKEN_BLK_BEGIN;
}

"}" {
   return TOKEN_BLK_END;
}

";" {
   return TOKEN_OP_END;
}

{OFFSET} {
   ef_debug(4, "OFFSET: %s\n", yytext);
   
   if (encode_offset(yytext, &yylval.fop) != E_SUCCESS)
      SCRIPT_ERROR("Offset \"%s\" not recognized", yytext);
   
   return TOKEN_OFFSET;
}

{FUNCTION} {
   ef_debug(4, "FUNCTION: %s\n", yytext);
   
   if (encode_function(yytext, &yylval.fop) != E_SUCCESS)
      SCRIPT_ERROR("Function \"%s\" not recognized", yytext);
   
   return TOKEN_FUNCTION;
}

{CONST} {
   ef_debug(4, "CONST: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != E_SUCCESS)
      SCRIPT_ERROR("Constant \"%s\" not recognized", yytext);
   
   return TOKEN_CONST;
}

{STRING} {
   ef_debug(4, "STRING: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != E_SUCCESS)
      SCRIPT_ERROR("Invalid string [%s]", yytext);
   
   return TOKEN_STRING;
}

{IPADDR} {
   ef_debug(4, "IPADDR: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != E_SUCCESS)
      SCRIPT_ERROR("Invalid ip address [%s]", yytext);
  
   /* ip addresses are translated into network order integer */
   return TOKEN_CONST;
}

{IP6ADDR} {
   ef_debug(4, "IP6ADDR: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != E_SUCCESS)
      SCRIPT_ERROR("Invalid ipv6 address [%s]", yytext);
  
   /* ip addresses are translated into network order integer */
   return TOKEN_CONST;
}

{SPACES}       /* eat up the blank spaces */

"/*".*"*/"     /* eat up one line comments */
"#".*

[\n\r] {
   /* increment the line number (used for error reporting) */
   EF_GBL->lineno++;
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

