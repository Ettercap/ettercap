/*
    ettercap -- content filtering engine module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_filter.c,v 1.2 2003/08/28 19:55:20 alor Exp $
*/

#include <ec.h>
#include <ec_filter.h>

/* proto */

int filter_engine(struct filter_op *fop, struct packet_object *po);

/*******************************************/

/*
 * JIT interpreter for binary filters.
 * it process the filter_ops and apply the instructions
 * on the given packet object
 */
int filter_engine(struct filter_op *fop, struct packet_object *po)
{
   int i = 0;
   
   printf("Filter Engine\n");


   do {

      switch (fop[i].opcode) {
         case FOP_TEST:
            printf("OPCODE: %d TEST : GOTO %d \n", fop[i].opcode, fop[i].jmp);
            break;
            
         case FOP_FUNC:
            printf("OPCODE: %d FUNC %d : GOTO %d\n", fop[i].opcode, fop[i].func.opcode, fop[i].jmp);
            break;
            
         case FOP_JMP:
            printf("OPCODE: %d JMP : GOTO %d\n", fop[i].opcode, fop[i].jmp);
            break;
            
         case FOP_DROP:
            printf("OPCODE: %d DROP : GOTO %d\n", fop[i].opcode, fop[i].jmp);
            break;
      }
      
   } while(fop[i++].opcode != FOP_EXIT);
   
   return 0;
}

/* EOF */

// vim:ts=3:expandtab

