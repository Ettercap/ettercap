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

    $Id: ef_compiler.c,v 1.3 2003/09/27 17:22:24 alor Exp $
*/

#include <ef.h>
#include <ef_functions.h>

/* globals */

struct block *init;

/* protos */

int compiler_set_init(struct block *blk);
struct filter_op * compile_tree(void);
struct block * compiler_add_block(struct instruction *ins, struct block *blk);
struct instruction * compiler_create_instruction(struct filter_op *fop);


/*******************************************/

/*
 * set the entry point of the filter tree
 */
int compiler_set_init(struct block *blk)
{
   BUG(blk == NULL);
   init = blk;
   return ESUCCESS;
}

/*
 * allocate an instruction container
 */
struct instruction * compiler_create_instruction(struct filter_op *fop)
{
   struct instruction *ins;

   SAFE_CALLOC(ins, 1, sizeof(struct instruction));
   
   return NULL;
}

/*
 * add an instruction to a block
 */
struct block * compiler_add_block(struct instruction *ins, struct block *blk)
{
   
   return NULL;
}


/*
 * 
 * parses the tree and produce a compiled
 * array of filter_op
 */
struct filter_op * compile_tree(void)
{
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

