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

    $Id: ef_syntax.l,v 1.12 2003/09/30 16:38:15 alor Exp $
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
   ef_debug(4, "IF\n");
   return TOKEN_IF;
}

"else" {
   ef_debug(4, "ELSE\n");
   return TOKEN_ELSE;
}

"!" {
   ef_debug(3, "NOT\n");
   return TOKEN_OP_NOT;
}

"&&" {
   ef_debug(3, "AND\n");
   return TOKEN_OP_AND;
}

"||" {
   ef_debug(3, "OR\n");
   return TOKEN_OP_OR;
}

"==" {
   ef_debug(3, "CMP EQ\n");
   return TOKEN_OP_CMP_EQ;
}

"<" {
   ef_debug(3, "CMP LT\n");
   return TOKEN_OP_CMP_LT;
}

">" {
   ef_debug(3, "CMP GT\n");
   return TOKEN_OP_CMP_GT;
}

"<=" {
   ef_debug(3, "CMP LEQ\n");
   return TOKEN_OP_CMP_LEQ;
}

">=" {
   ef_debug(3, "CMP GEQ\n");
   return TOKEN_OP_CMP_GEQ;
}

"=" {
   ef_debug(3, "ASSIGN\n");
   return TOKEN_OP_ASSIGN;
}

"*" {
   ef_debug(5, "*\n");
   return TOKEN_OP_MUL;
}

"+" {
   ef_debug(5, "+\n");
   return TOKEN_OP_ADD;
}

"-" {
   ef_debug(5, "-\n");
   return TOKEN_OP_SUB;
}

"/" {
   ef_debug(5, "/\n");
   return TOKEN_OP_DIV;
}

"(" {
   ef_debug(4, "(\n");
   return TOKEN_PAR_OPEN;
}

")" {
   ef_debug(4, ")\n");
   return TOKEN_PAR_CLOSE;
}

"{" {
   ef_debug(4, "{\n");
   return TOKEN_BLK_BEGIN;
}

"}" {
   ef_debug(4, "}\n");
   return TOKEN_BLK_END;
}

";" {
   ef_debug(5, ";\n");
   return TOKEN_OP_END;
}

{OFFSET} {
   ef_debug(3, "OFFSET: %s\n", yytext);
   
   if (encode_offset(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Offset \"%s\" not recognized", yytext);
   
   return TOKEN_OFFSET;
}

{FUNCTION} {
   ef_debug(3, "FUNCTION: %s\n", yytext);
   
   if (encode_function(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Function \"%s\" not recognized", yytext);
   
   return TOKEN_FUNCTION;
}

{CONST} {
   ef_debug(3, "CONST: %s\n", yytext);
   
   if (encode_const(yytext, &yylval.fop) != ESUCCESS)
      SCRIPT_ERROR("Constant \"%s\" not recognized", yytext);
   
   return TOKEN_CONST;
}

{STRING} {
   ef_debug(3, "STRING: %s\n", yytext);
   
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

