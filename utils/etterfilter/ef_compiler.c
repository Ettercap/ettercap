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

    $Id: ef_compiler.c,v 1.4 2003/09/28 21:07:49 alor Exp $
*/

#include <ef.h>
#include <ef_functions.h>

/* globals */

struct block *tree_root;

/* protos */

int compiler_set_root(struct block *blk);
size_t compile_tree(struct filter_op **fop);
struct block * compiler_add_instr(struct instruction *ins, struct block *blk);
struct instruction * compiler_create_instruction(struct filter_op *fop);


/*******************************************/

/*
 * set the entry point of the filter tree
 */
int compiler_set_root(struct block *blk)
{
   BUG_IF(blk == NULL);
   tree_root = blk;
   return ESUCCESS;
}

/*
 * allocate an instruction container
 */
struct instruction * compiler_create_instruction(struct filter_op *fop)
{
   struct instruction *ins;

   SAFE_CALLOC(ins, 1, sizeof(struct instruction));
   
   /* copy the instruction */
   memcpy(&ins->fop, fop, sizeof(struct filter_op));

   return ins;
}

/*
 * add an instruction to a block
 */
struct block * compiler_add_instr(struct instruction *ins, struct block *blk)
{
   struct block *bl;

   SAFE_CALLOC(bl, 1, sizeof(struct block));

   /* copy the current instruction in the block */
   bl->type = BLK_INSTR;
   bl->un.ins = ins;

   /* link it to the old block chain */
   bl->next = blk;

   /* 
    * update the counter by adding the number
    * of instructions in the old block
    */
   bl->n = 1;
   if (blk != NULL)
      bl->n += blk->n;

   return bl;
}


/*
 * parses the tree and produce a compiled
 * array of filter_op
 */
size_t compile_tree(struct filter_op **fop)
{
   int i = 1;
   struct block *b = tree_root;
   struct filter_op *array;

   NOT_IMPLEMENTED();

   /* sanity check */
   BUG_IF(b == NULL);

   /* make sure the realloc will allocate the first time */
   array = NULL;
   
   do {

      /* alloc the array */
      SAFE_REALLOC(array, i * sizeof(struct filter_op));
     
      /* copy the instruction */
      memcpy(&array[i - 1], b->un.ins, sizeof(struct filter_op));
      
      print_fop(&(array[i - 1]), i - 1);
      
      i++;
      
   } while ((b = b->next));

   /* always append the exit function to a script */
   SAFE_REALLOC(array, i * sizeof(struct filter_op));
   array[i - 1].opcode = FOP_EXIT;
   
   /* return the pointer to the array */
   *fop = array;
   
   return (i);
}


/* EOF */

// vim:ts=3:expandtab

