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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_filter.c,v 1.8 2003/09/13 10:04:13 alor Exp $
*/

#include <ec.h>
#include <ec_filter.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>

#define JIT_FAULT(x, ...) FATAL_ERROR("JIT FAULT: " x, ## __VA_ARGS__)

/* protos */

int filter_engine(struct filter_op *fop, struct packet_object *po);
static int execute_test(struct filter_op *fop, struct packet_object *po);
static int execute_assign(struct filter_op *fop, struct packet_object *po);
static int execute_func(struct filter_op *fop, struct packet_object *po);

static int func_search(struct filter_op *fop, struct packet_object *po);
static int func_regex(struct filter_op *fop, struct packet_object *po);
static int func_replace(struct filter_op *fop, struct packet_object *po);
static int func_log(struct filter_op *fop, struct packet_object *po);
static int func_drop(struct packet_object *po);
static int func_exec(struct filter_op *fop);

static int cmp_eq(u_int32 a, u_int32 b);
static int cmp_lt(u_int32 a, u_int32 b);
static int cmp_gt(u_int32 a, u_int32 b);
static int cmp_leq(u_int32 a, u_int32 b);
static int cmp_geq(u_int32 a, u_int32 b);
/*******************************************/

/*
 * JIT interpreter for binary filters.
 * it process the filter_ops and apply the instructions
 * on the given packet object
 */
int filter_engine(struct filter_op *fop, struct packet_object *po)
{
   u_int32 eip = 0;
   u_int32 flags = 0;
      #define FLAG_FALSE   0
      #define FLAG_TRUE    1
   
   /* loop until EXIT */
   while (fop[eip].opcode != FOP_EXIT) {

      switch (fop[eip].opcode) {
         case FOP_TEST:
            printf("%d OPCODE: TEST \n", eip);
            if (execute_test(&fop[eip], po) == FLAG_TRUE)
               flags |= FLAG_TRUE;
            else
               flags &= ~(FLAG_TRUE);
            
            break;
            
         case FOP_ASSIGN:
            printf("%d OPCODE: ASSIGN \n", eip);
            execute_assign(&fop[eip], po);
            /* assignment always return true */
            flags |= FLAG_TRUE;
            
            break;
            
         case FOP_FUNC:
            printf("%d OPCODE: FUNC %d \n", eip, fop[eip].op.func.opcode);
            if (execute_func(&fop[eip], po) == FLAG_TRUE)
               flags |= FLAG_TRUE;
            else
               flags &= ~(FLAG_TRUE);

            break;
            
         case FOP_JMP:
            printf("%d OPCODE: JMP %d\n", eip, fop[eip].op.jmp);
            
            /* jump the the next eip */
            eip = fop[eip].op.jmp;
            continue;

            break;
            
         case FOP_JTRUE:
            printf("%d OPCODE: JTRUE %d\n", eip, fop[eip].op.jmp);
            
            /* jump the the next eip if the TRUE FLAG is set*/
            if (flags & FLAG_TRUE) {
               eip = fop[eip].op.jmp;
               continue;
            }
            continue;

            break;
            
         case FOP_JFALSE:
            printf("%d OPCODE: JFALSE %d\n", eip, fop[eip].op.jmp);
            
            /* jump the the next eip if the TRUE FLAG is NOT set */
            if (!(flags & FLAG_TRUE)) {
               eip = fop[eip].op.jmp;
               continue;
            }

            break;
      }
    
      /* autoincrement the instruction pointer */
      eip++;
   }
            
   printf("%d OPCODE: EXIT\n", eip);
   
   return 0;
}


/* 
 * execute a function.
 * return FLAG_TRUE if the function was successful
 */
static int execute_func(struct filter_op *fop, struct packet_object *po)
{
   switch (fop->op.func.opcode) {
      case FFUNC_SEARCH:
         /* search the string */
         if (func_search(fop, po) == ESUCCESS)
            return FLAG_TRUE;
         break;
         
      case FFUNC_REGEX:
         /* search the string with a regex */
         if (func_regex(fop, po) == ESUCCESS)
            return FLAG_TRUE;
         break;

      case FFUNC_REPLACE:
         /* replace the string */
         if (func_replace(fop, po) == ESUCCESS)
            return FLAG_TRUE;
         break;
         
      case FFUNC_LOG:
         /* log the packet */
         if (func_log(fop, po) == ESUCCESS)
            return FLAG_TRUE;
         break;
         
      case FFUNC_DROP:
         /* drop the packet */
         func_drop(po);
         return FLAG_TRUE;
         break;
         
      case FFUNC_MSG:
         /* display the message to the user */
         USER_MSG("%s", fop->op.func.value);
         return FLAG_TRUE;
         break;
         
      case FFUNC_EXEC:
         /* execute the command */
         if (func_exec(fop) == ESUCCESS)
            return FLAG_TRUE;
         break;
         
      default:
         JIT_FAULT("unsupported function [%d]", fop->op.func.opcode);
         break;
   }

   return FLAG_FALSE;
}

/* 
 * execute a test.
 * return FLAG_TRUE if the test was successful
 */
static int execute_test(struct filter_op *fop, struct packet_object *po)
{
   /* initialize to the beginning of the packet */
   u_char *base = po->L2.header;
   int (*cmp_func)(u_int32, u_int32);

   /* 
    * point to the right base.
    * if the test is L3.ttl, we have to start from
    * L3.header to count for offset.
    */
   switch (fop->op.test.level) {
      case 2:
         base = po->L2.header;
         break;
      case 3:
         base = po->L3.header;
         break;
      case 4:
         base = po->L4.header;
         break;
      case 5:
         base = po->DATA.data;
         break;
      case 6:
         base = po->DATA.disp_data;
         break;
      default:
         JIT_FAULT("unsupported test level [%d]", fop->op.test.level);
         break;
   }

   /* se the pointer to the comparison function */
   switch(fop->op.test.op) {
      case TEST_EQ:
         cmp_func = &cmp_eq;
         break;
      case TEST_LT:
         cmp_func = &cmp_lt;
         break;
      case TEST_GT:
         cmp_func = &cmp_gt;
         break;
      case TEST_LEQ:
         cmp_func = &cmp_leq;
         break;
      case TEST_GEQ:
         cmp_func = &cmp_geq;
         break;
      default:
         JIT_FAULT("unsupported test operation");
         break;
           
   }
   
   /* 
    * get the value with the proper size.
    * 0 is a special case for strings (even binary) 
    */
   switch (fop->op.test.size) {
      case 0:
         /* string comparison */
         if (cmp_func(memcmp(base + fop->op.test.offset, fop->op.test.string, fop->op.test.string_len), 0) )
            return FLAG_TRUE;
         break;
      case 1:
         /* char comparison */
         if (cmp_func(*(u_int8 *)(base + fop->op.test.offset), (fop->op.test.value & 0xff)) )
            return FLAG_TRUE;
         break;
      case 2:
         /* short int comparison */
         if (cmp_func(htons(*(u_int16 *)(base + fop->op.test.offset)), (fop->op.test.value & 0xffff)) )
            return FLAG_TRUE;
         break;
      case 4:
         /* int comparison */
         if (cmp_func(htonl(*(u_int32 *)(base + fop->op.test.offset)),(fop->op.test.value & 0xffffffff)) )
            return FLAG_TRUE;
         break;
      default:
         JIT_FAULT("unsupported test size [%d]", fop->op.test.size);
         break;
   }
         
   return FLAG_FALSE;
}

/* 
 * make an assignment.
 */
static int execute_assign(struct filter_op *fop, struct packet_object *po)
{
   /* initialize to the beginning of the packet */
   u_char *base = po->L2.header;

   DEBUG_MSG("filter engine: execute_assign: L%d O%d S%d", fop->op.assign.level, fop->op.assign.offset, fop->op.assign.size);
   
   /* 
    * point to the right base.
    */
   switch (fop->op.assign.level) {
      case 2:
         base = po->L2.header;
         break;
      case 3:
         base = po->L3.header;
         break;
      case 4:
         base = po->L4.header;
         break;
      case 5:
         base = po->DATA.data;
         break;
      default:
         JIT_FAULT("unsupported assignment level [%d]", fop->op.assign.level);
         break;
   }

   /* 
    * get the value with the proper size.
    * 0 is a special case for strings (even binary) 
    */
   switch (fop->op.assign.size) {
      case 0:
         memcpy(base + fop->op.assign.offset, fop->op.assign.string, fop->op.assign.string_len);
         break;
      case 1:
         *(u_int8 *)(base + fop->op.assign.offset) = (fop->op.assign.value & 0xff);
         break;
      case 2:
         *(u_int16 *)(base + fop->op.assign.offset) = ntohs(fop->op.assign.value & 0xffff); 
         break;
      case 4:
         *(u_int32 *)(base + fop->op.assign.offset) = ntohl(fop->op.assign.value & 0xffffffff);
         break;
      default:
         JIT_FAULT("unsupported assign size [%d]", fop->op.assign.size);
         break;
   }
      
   /* mark the packet as modified */
   po->flags |= PO_MODIFIED;

   return FLAG_TRUE;
}


/*
 * search a string and return TRUE if found
 */
static int func_search(struct filter_op *fop, struct packet_object *po)
{
   switch (fop->op.func.level) {
      case 5:
         /* search in the real packet */
         if (memmem(po->DATA.data, po->DATA.len, fop->op.func.value, fop->op.func.value_len))
            return ESUCCESS;
         break;
      case 6:
         /* search in the decoded/decrypted packet */
         if (memmem(po->DATA.disp_data, po->DATA.disp_len, fop->op.func.value, fop->op.func.value_len))
            return ESUCCESS;
         break;
      default:
         JIT_FAULT("unsupported search level [%d]", fop->op.func.level);
         break;
   }
   
   return -ENOTFOUND;
}

/*
 * search a string with a regex and return TRUE if found
 */
static int func_regex(struct filter_op *fop, struct packet_object *po)
{
   int err;
   regex_t regex;
   char errbuf[100];

   /* prepare the regex */
   err = regcomp(&regex, fop->op.func.value, REG_EXTENDED | REG_NOSUB | REG_ICASE );
   if (err) {
      regerror(err, &regex, errbuf, sizeof(errbuf));
      JIT_FAULT("%s", errbuf);
   } 
   
   switch (fop->op.func.level) {
      case 5:
         /* search in the real packet */
         if (regexec(&regex, po->DATA.data, 0, NULL, 0) == 0)
            return ESUCCESS;
         break;
      case 6:
         /* search in the decoded/decrypted packet */
         if (regexec(&regex, po->DATA.disp_data, 0, NULL, 0) == 0)
            return ESUCCESS;
         break;
      default:
         JIT_FAULT("unsupported regex level [%d]", fop->op.func.level);
         break;
   }

   return -ENOTFOUND;
}

/* 
 * replace a string in the packet object DATA.data
 */
static int func_replace(struct filter_op *fop, struct packet_object *po)
{
   u_int8 *ptr = po->DATA.data;
   u_int8 *end = po->DATA.data + po->DATA.len;
   u_int32 len;
   size_t slen = fop->op.func.value_len;
   size_t rlen = fop->op.func.value2_len;
  
   /* check if it exist at least one */
   if (!memmem(po->DATA.data, po->DATA.len, fop->op.func.value, fop->op.func.value_len) )
      return -ENOTFOUND;

   DEBUG_MSG("filter engine: func_replace");
  
   /* do the replacement */
   do {
      /* the len of the buffer to be analized */
      len = end - ptr;

      /* search the string */
      ptr = memmem(ptr, len, fop->op.func.value, slen);
      /* update the len */
      len -= fop->op.func.value_len;

      /* string no found, exit */
      if (ptr == NULL)
         break;
      
      /* move the buffer to make room for the replacement string */   
      memmove(ptr + rlen, ptr + slen, len); 
      /* copy the replacemente string */
      memcpy(ptr, fop->op.func.value2, rlen);
      /* move the ptr after the replaced string */
      ptr += rlen; 
      /* set the delta */
      po->delta += rlen - slen;
      /* adjust the new buffer end */
      end += po->delta;
                                                            
      /* mark the packet as modified */
      po->flags |= PO_MODIFIED;

      /* if the new packet exceed the mtu */
      /* XXX - TODO */
      //if (po->len + po->delta > GBL_IFACE->mtu - po->L2.len)
     
   } while(ptr != NULL && ptr < end);
  

   return ESUCCESS;
}


/*
 * log the packet to a file
 */
static int func_log(struct filter_op *fop, struct packet_object *po)
{
   int fd;

   DEBUG_MSG("filter engine: func_log");
   
   /* open the file */
   fd = open(fop->op.func.value, O_CREAT | O_APPEND | O_RDWR, 0600);
   if (fd == -1) {
      USER_MSG("filter engine: Cannot open file %s\n", fop->op.func.value);
      return -EFATAL;
   }

   /* which data should I have to log ? */
   switch(fop->op.func.level) {
      case 5:
         if (write(fd, po->DATA.data, po->DATA.len) < 0)
            USER_MSG("filter engine: Cannot write to file...%d\n", errno);
         break;
      case 6:
         if (write(fd, po->DATA.disp_data, po->DATA.disp_len) < 0)
            USER_MSG("filter engine: Cannot write to file...\n");
         break;
      default:
         JIT_FAULT("unsupported log level [%d]", fop->op.func.level);
         break;
   }

   /* close the file */
   close(fd);
   
   return ESUCCESS;
}

/*
 * drop the packet
 */
static int func_drop(struct packet_object *po)
{
   DEBUG_MSG("filter engine: func_drop");
   
   /* se the flag to be dropped */
   po->flags |= PO_DROPPED;

   /* the delta is all the payload */
   po->delta = po->DATA.len;
   
   return ESUCCESS;
}

/*
 * execute the given command
 */
static int func_exec(struct filter_op *fop)
{
   DEBUG_MSG("filter engine: func_exec: %s", fop->op.func.value);
   
   /* 
    * the command must be executed by a child.
    * we are forwding packets, and we cannot wait 
    * for the execution of the command 
    */
   if (!fork()) {
      char **param = NULL;
      char *q = fop->op.func.value;
      char *p;
      int i = 0;

      /* split the string */
      for (p = strsep(&q, " "); p != NULL; p = strsep(&q, " ")) {
         /* allocate the array */
         param = realloc(param, (i + 1) * sizeof(char *));
         /* copy the tokens in the array */
         param[i++] = strdup(p); 
      }
      
      /* NULL terminate the array */
      param = realloc(param, (i + 1) * sizeof(char *));
      param[i] = NULL;
     
      /* 
       * close input, output and error.
       * we don't want to clobber the interface 
       * with output from the child
       */
      close(fileno(stdin));
      close(fileno(stdout));
      close(fileno(stderr));
      
      /* execute the command */
      execve(param[0], param, NULL);

      /* reached on errors */
      exit(-1);
   }
      
   return ESUCCESS;
}

/*
 * functions for comparisons
 */
static int cmp_eq(u_int32 a, u_int32 b)
{
   return (a == b);
}

static int cmp_lt(u_int32 a, u_int32 b)
{
   return (a < b);
}

static int cmp_gt(u_int32 a, u_int32 b)
{
   return (a > b);
}

static int cmp_leq(u_int32 a, u_int32 b)
{
   return (a <= b);
}

static int cmp_geq(u_int32 a, u_int32 b)
{
   return (a >= b);
}


/* EOF */

// vim:ts=3:expandtab

