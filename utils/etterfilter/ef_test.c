/*
    etterfilter -- test module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_test.c,v 1.4 2003/09/13 10:04:15 alor Exp $
*/

#include <ef.h>
#include <ec_filter.h>
#include <ec_packet.h>

/* protos */

void test_filter(void);

/*******************************************/

/*
 * test a binary filter against a given file 
 */
void test_filter(void)
{
   struct filter_op istr[6];
   struct packet_object po;

   memset(&istr, 0, sizeof(istr));
   
   /* if (DATA.data, search("OpenSSH")) { */
   istr[0].opcode = FOP_FUNC;
   istr[0].op.func.opcode = FFUNC_SEARCH;
   istr[0].op.func.level = 5;
   strcpy(istr[0].op.func.value, "OpenSSH");
   istr[0].op.func.value_len = strlen(istr[0].op.func.value);
   
   istr[1].opcode = FOP_JFALSE;
   istr[1].op.jmp = 5;

   /* replace("SSH-1.99", "SSH-1.51"); */
   istr[2].opcode = FOP_FUNC;
   istr[2].op.func.opcode = FFUNC_REPLACE;
   istr[2].op.func.level = 5;
   strcpy(istr[2].op.func.value, "SSH-1.99");
   istr[2].op.func.value_len = strlen(istr[2].op.func.value);
   strcpy(istr[2].op.func.value2, "SSH-1.51");
   istr[2].op.func.value2_len = strlen(istr[2].op.func.value2);
  
   /* msg("SSH downgraded to version 1"); */
   istr[3].opcode = FOP_FUNC;
   istr[3].op.func.opcode = FFUNC_MSG;
   strcpy(istr[3].op.func.value, "SSH downgraded to version 1\n");
   
   istr[4].opcode = FOP_JMP;
   istr[4].op.jmp = 6;
   
   /* } else { DATA.data + 3 = '+' */
   istr[5].opcode = FOP_ASSIGN;
   istr[5].op.assign.level = 5;
   istr[5].op.assign.offset = 3;
   istr[5].op.assign.size = 1;
   istr[5].op.assign.value = '+';

   /* } */
   istr[6].opcode = FOP_EXIT;
  
   memset(&po, 0, sizeof(struct packet_object));

   po.DATA.data = strdup("SSH-1.99-OpenSSH_3.6.1p2");
   po.DATA.len = strlen(po.DATA.data);
   
   
   printf("BEFORE: %s\n", po.DATA.data);
   
   filter_engine(istr, &po);

   printf("AFTER : %s\n", po.DATA.data);
   
}



/* EOF */

// vim:ts=3:expandtab

