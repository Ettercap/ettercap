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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterfilter/ef_test.c,v 1.1 2003/08/28 19:55:20 alor Exp $
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
 
   /* if (DATA.data + 10 == 'O') { */
   istr[0].opcode = FOP_TEST;
   istr[0].op.offset = 10;
   istr[0].op.value = 'O';
   istr[0].jmp = 2;
   
   istr[1].opcode = FOP_JMP;
   istr[1].jmp = 3;

   /* replace(DATA.data, "SSH-1.99", "SSH-1.51"); */
   istr[2].opcode = FOP_FUNC;
   istr[2].func.opcode = FFUNC_REPLACE;
   strcpy(istr[2].func.value, "SSH-1.99");
   istr[2].func.value_len = strlen("SSH-1.99");
   strcpy(istr[2].func.value2, "SSH-1.51");
   istr[2].func.value2_len = strlen("SSH-1.51");
   istr[2].jmp = 2;
   
   istr[3].opcode = FOP_JMP;
   istr[3].jmp = 5;
   
   /* } else { replace(DATA.data, "3.6.1", "x.x.x") */
   istr[4].opcode = FOP_FUNC;
   istr[4].func.opcode = FFUNC_REPLACE;
   strcpy(istr[4].func.value, "3.6.1");
   istr[4].func.value_len = strlen("3.6.1");
   strcpy(istr[4].func.value2, "x.x.x");
   istr[4].func.value2_len = strlen("x.x.x");
   istr[4].jmp = 5;

   /* } */
   istr[5].opcode = FOP_EXIT;
   
   
   po.DATA.data = strdup("SSH-1.99-OpenSSH_3.6.1p2");
   po.DATA.len = strlen(po.DATA.data);
   
   
   printf("BEFORE: %s\n", po.DATA.data);
   
   filter_engine(istr, &po);

   printf("AFTER : %s\n", po.DATA.data);
   
}



/* EOF */

// vim:ts=3:expandtab

