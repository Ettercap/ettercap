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

    $Id: ec_filter.c,v 1.24 2003/10/05 20:44:41 alor Exp $
*/

#include <ec.h>
#include <ec_filter.h>
#include <ec_strings.h>
#include <ec_version.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <regex.h>
#ifdef HAVE_PCRE
   #include <pcre.h>
#endif

#define JIT_FAULT(x, ...) USER_MSG("JIT FILTER FAULT: " x, ## __VA_ARGS__)

/* protos */

int filter_load_file(char *filename, struct filter_env *fenv);
void filter_unload(struct filter_env *fenv);
static void reconstruct_strings(struct filter_env *fenv, struct filter_header *fh);
static int compile_regex(struct filter_env *fenv, struct filter_header *fh);
   
int filter_engine(struct filter_op *fop, struct packet_object *po);
static int execute_test(struct filter_op *fop, struct packet_object *po);
static int execute_assign(struct filter_op *fop, struct packet_object *po);
static int execute_func(struct filter_op *fop, struct packet_object *po);

static int func_search(struct filter_op *fop, struct packet_object *po);
static int func_regex(struct filter_op *fop, struct packet_object *po);
static int func_pcre(struct filter_op *fop, struct packet_object *po);
static int func_replace(struct filter_op *fop, struct packet_object *po);
static int func_inject(struct filter_op *fop, struct packet_object *po);
static int func_log(struct filter_op *fop, struct packet_object *po);
static int func_drop(struct packet_object *po);
static int func_exec(struct filter_op *fop);

static int cmp_eq(u_int32 a, u_int32 b);
static int cmp_neq(u_int32 a, u_int32 b);
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
  
   /* sanity check */
   BUG_IF(fop == NULL);

   /* loop until EXIT */
   while (fop[eip].opcode != FOP_EXIT) {

      switch (fop[eip].opcode) {
         case FOP_TEST:
            if (execute_test(&fop[eip], po) == FLAG_TRUE)
               flags |= FLAG_TRUE;
            else
               flags &= ~(FLAG_TRUE);
            
            break;
            
         case FOP_ASSIGN:
            execute_assign(&fop[eip], po);
            /* assignment always return true */
            flags |= FLAG_TRUE;
            
            break;
            
         case FOP_FUNC:
            if (execute_func(&fop[eip], po) == FLAG_TRUE)
               flags |= FLAG_TRUE;
            else
               flags &= ~(FLAG_TRUE);

            break;
            
         case FOP_JMP:
            /* jump the the next eip */
            eip = fop[eip].op.jmp;
            continue;

            break;
            
         case FOP_JTRUE:
            /* jump the the next eip if the TRUE FLAG is set*/
            if (flags & FLAG_TRUE) {
               eip = fop[eip].op.jmp;
               continue;
            }
            break;
            
         case FOP_JFALSE:
            /* jump the the next eip if the TRUE FLAG is NOT set */
            if (!(flags & FLAG_TRUE)) {
               eip = fop[eip].op.jmp;
               continue;
            }
            break;
            
         default:
            JIT_FAULT("unsupported opcode [%d] (execution interrupted)", fop[eip].opcode);
            return 0;
            break;
      }
    
      /* autoincrement the instruction pointer */
      eip++;
   }

   return 0;
}


/* 
 * execute a function.
 * return FLAG_TRUE if the function was successful
 */
static int execute_func(struct filter_op *fop, struct packet_object *po)
{
   switch (fop->op.func.op) {
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
         
      case FFUNC_PCRE:
         /* evaluate a perl regex */
         if (func_pcre(fop, po) == ESUCCESS)
            return FLAG_TRUE;
         break;

      case FFUNC_REPLACE:
         /* replace the string */
         if (func_replace(fop, po) == ESUCCESS)
            return FLAG_TRUE;
         break;
         
      case FFUNC_INJECT:
         /* replace the string */
         if (func_inject(fop, po) == ESUCCESS)
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
         USER_MSG("%s", fop->op.func.string);
         return FLAG_TRUE;
         break;
         
      case FFUNC_EXEC:
         /* execute the command */
         if (func_exec(fop) == ESUCCESS)
            return FLAG_TRUE;
         break;
         
      default:
         JIT_FAULT("unsupported function [%d]", fop->op.func.op);
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
   int (*cmp_func)(u_int32, u_int32) = &cmp_eq;

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
      case FTEST_EQ:
         cmp_func = &cmp_eq;
         break;
      case FTEST_NEQ:
         cmp_func = &cmp_neq;
         break;
      case FTEST_LT:
         cmp_func = &cmp_lt;
         break;
      case FTEST_GT:
         cmp_func = &cmp_gt;
         break;
      case FTEST_LEQ:
         cmp_func = &cmp_leq;
         break;
      case FTEST_GEQ:
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
         if (cmp_func(memcmp(base + fop->op.test.offset, fop->op.test.string, fop->op.test.slen), 0) )
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
         if (cmp_func(htonl(*(u_int32 *)(base + fop->op.test.offset)), (fop->op.test.value & 0xffffffff)) )
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
         memcpy(base + fop->op.assign.offset, fop->op.assign.string, fop->op.assign.slen);
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
         if (memmem(po->DATA.data, po->DATA.len, fop->op.func.string, fop->op.func.slen))
            return ESUCCESS;
         break;
      case 6:
         /* search in the decoded/decrypted packet */
         if (memmem(po->DATA.disp_data, po->DATA.disp_len, fop->op.func.string, fop->op.func.slen))
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
   switch (fop->op.func.level) {
      case 5:
         /* search in the real packet */
         if (regexec(fop->op.func.ropt->regex, po->DATA.data, 0, NULL, 0) == 0)
            return ESUCCESS;
         break;
      case 6:
         /* search in the decoded/decrypted packet */
         if (regexec(fop->op.func.ropt->regex, po->DATA.disp_data, 0, NULL, 0) == 0)
            return ESUCCESS;
         break;
      default:
         JIT_FAULT("unsupported regex level [%d]", fop->op.func.level);
         break;
   }

   return -ENOTFOUND;
}


/*
 * evaluate a perl regex and return TRUE if found
 */
static int func_pcre(struct filter_op *fop, struct packet_object *po)
{
#ifndef HAVE_PCRE
   JIT_FAULT("pcre_regex support not compiled in ettercap");
   return -ENOTFOUND
#else
   
   switch (fop->op.func.level) {
      case 5:
         /* search in the real packet */
         if ( pcre_exec(fop->op.func.ropt->pregex, fop->op.func.ropt->preg_extra, po->DATA.data, po->DATA.len, 0, 0, NULL, 0) < 0)
            return -ENOTFOUND;
         break;
      case 6:
         /* search in the decoded one */
         if ( pcre_exec(fop->op.func.ropt->pregex, fop->op.func.ropt->preg_extra, po->DATA.disp_data, po->DATA.disp_len, 0, 0, NULL, 0) < 0)
            return -ENOTFOUND;
         break;
      default:
         JIT_FAULT("unsupported pcre_regex level [%d]", fop->op.func.level);
         break;
   }

   return ESUCCESS;
#endif
}


/* 
 * replace a string in the packet object DATA.data
 */
static int func_replace(struct filter_op *fop, struct packet_object *po)
{
   u_int8 *tmp;
   u_int8 *ptr;
   u_int8 *end;
   size_t len;
   size_t slen = fop->op.func.slen;
   size_t rlen = fop->op.func.rlen;
   int delta = 0;
   size_t max_len, new_len;
  
   /* 
    * calculate the max len of data this packet can contain.
    * subtract to the MTU all the headers len
    */
   max_len = GBL_IFACE->mtu - (po->L4.header - po->fwd_packet + po->L4.len);
  
   /* check if it exist at least one */
   if (!memmem(po->DATA.data, po->DATA.len, fop->op.func.string, fop->op.func.slen) )
      return -ENOTFOUND;

   DEBUG_MSG("filter engine: func_replace : max_len %d", max_len);

   /* make a copy of the buffer and operate on that */
   SAFE_CALLOC(tmp, po->DATA.len, sizeof(u_int8));
         
   memcpy(tmp, po->DATA.data, po->DATA.len);

   /* take the beginning and the end of the data */
   ptr = tmp;
   end = tmp + po->DATA.len;
   
   /* do the replacement */
   do {
      /* the len of the buffer to be analized */
      len = end - ptr;

      /* search the string */
      ptr = memmem(ptr, len, fop->op.func.string, slen);
      /* update the len */
      len -= fop->op.func.slen;

      /* string no found, exit */
      if (ptr == NULL)
         break;
      
      /* set the delta */
      delta += rlen - slen;

      /* resize the buffer to contain the new data */
      SAFE_REALLOC(tmp, po->DATA.len + delta);
      
      /* move the buffer to make room for the replacement string */   
      memmove(ptr + rlen, ptr + slen, len); 
      /* copy the replacemente string */
      memcpy(ptr, fop->op.func.replace, rlen);
      /* move the ptr after the replaced string */
      ptr += rlen; 
      /* adjust the new buffer end */
      end += delta;
                                                            
      /* mark the packet as modified */
      po->flags |= PO_MODIFIED;

   } while(ptr != NULL && ptr < end);
  
   /* if there was a modification, update the packet */
   if (po->flags & PO_MODIFIED) {

      /* the packet has exceeded the MTU */
      if (po->DATA.len + delta > max_len) {
         po->DATA.delta = max_len - po->DATA.len;
      } else {
         /* the new buffer fits the packet */
         po->DATA.delta = delta;
      }
      /* new lenght is the minimum between the max len and the modified len */ 
      new_len = MIN(po->DATA.len + po->DATA.delta, max_len);
      /* wipe the old buffer */
      memset(po->DATA.data, 0, po->DATA.len);
      /* check if we are overflowing pcap buffer */
      BUG(GBL_PCAP->snaplen - (po->L4.header - po->fwd_packet + po->L4.len) < new_len);
      /* copy the temp buffer on the original packet */
      memcpy(po->DATA.data, tmp, new_len);
      
      /* copy the rest in the inject buffer */
      if (delta != po->DATA.delta) {
         SAFE_CALLOC(po->inject, po->DATA.len + delta - max_len, sizeof(u_char));
         memcpy(po->inject, tmp + new_len, po->DATA.len + delta - max_len);
      }
   }
   
   SAFE_FREE(tmp);

   return ESUCCESS;
}

/*
 * inject a file into the communication
 */
static int func_inject(struct filter_op *fop, struct packet_object *po)
{
   int fd;
   void *file;
   size_t size;

   DEBUG_MSG("filter engine: func_inject %s", fop->op.func.string);
   
   /* open the file */
   if ((fd = open(fop->op.func.string, O_RDONLY)) == -1) {
      USER_MSG("filter engine: inject(): File not found (%s)\n", fop->op.func.string);
      return -EFATAL;
   }

   /* get the size */
   size = lseek(fd, 0, SEEK_END);

   /* load the file in memory */
   file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
   if (file == MAP_FAILED) {
      USER_MSG("filter engine: inject(): Cannot mmap file");
      return -EFATAL;
   }
 
   SAFE_CALLOC(po->inject, size, sizeof(u_char));
   
   /* copy the file into the buffer */
   memcpy(po->inject, file, size);

   /* set the size */
   po->inject_len = size;
   
   /* close and unmap the file */
   close(fd);
   munmap(file, size);
   
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
   fd = open(fop->op.func.string, O_CREAT | O_APPEND | O_RDWR, 0600);
   if (fd == -1) {
      USER_MSG("filter engine: Cannot open file %s\n", fop->op.func.string);
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
   po->DATA.delta = po->DATA.len;
   
   return ESUCCESS;
}

/*
 * execute the given command
 */
static int func_exec(struct filter_op *fop)
{
   DEBUG_MSG("filter engine: func_exec: %s", fop->op.func.string);
   
   /* 
    * the command must be executed by a child.
    * we are forwding packets, and we cannot wait 
    * for the execution of the command 
    */
   if (!fork()) {
      char **param = NULL;
      char *q = fop->op.func.string;
      char *p;
      int i = 0;

      /* split the string */
      for (p = strsep(&q, " "); p != NULL; p = strsep(&q, " ")) {
         /* allocate the array */
         SAFE_REALLOC(param, (i + 1) * sizeof(char *));
         
         /* copy the tokens in the array */
         param[i++] = strdup(p); 
      }
      
      /* NULL terminate the array */
      SAFE_REALLOC(param, (i + 1) * sizeof(char *));
      
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

static int cmp_neq(u_int32 a, u_int32 b)
{
   return (a != b);
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

/*
 * load the filter from a file 
 */
int filter_load_file(char *filename, struct filter_env *fenv)
{
   int fd;
   void *file;
   size_t size;
   struct filter_header fh;

   DEBUG_MSG("filter_load_file (%s)", filename);
   
   /* open the file */
   if ((fd = open(filename, O_RDONLY)) == -1)
      FATAL_MSG("File not found or permission denied");

   /* read the header */
   if (read(fd, &fh, sizeof(struct filter_header)) != sizeof(struct filter_header))
      FATAL_MSG("The file is corrupted");

   /* sanity checks */
   if (fh.magic != htons(EC_FILTER_MAGIC))
      FATAL_MSG("Bad magic in filter file");
  
   /* which version has compiled the filter ? */
   if (strcmp(fh.version, EC_VERSION))
      FATAL_MSG("Filter compiled for a different version");
   
   /* get the size */
   size = lseek(fd, 0, SEEK_END);

   /* 
    * load the file in memory 
    * skipping the initial header
    */
   file = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
   if (file == MAP_FAILED)
      FATAL_MSG("Cannot mmap file");

   /* make sure we don't override a previous filter */
   filter_unload(fenv);

   /* set the global variables */
   fenv->map = file;
   fenv->chain = (struct filter_op *)(file + fh.code);
   fenv->len = size - sizeof(struct filter_header) - fh.code;

   /* the mmap will remain active even if we close the fd */
   close(fd);

   /* 
    * adjust all the string pointers 
    * they must point to the data segment
    */
   reconstruct_strings(fenv, &fh);

   /* compile the regex to speed up the matching */
   if (compile_regex(fenv, &fh) != ESUCCESS)
      return -EFATAL;
   
   USER_MSG("Content filters loaded from %s...\n", filename);
   
   return ESUCCESS;
}

/* 
 * unload a filter chain.
 */
void filter_unload(struct filter_env *fenv)
{
   size_t i = 0;
   struct filter_op *fop = fenv->chain;
   
   DEBUG_MSG("filter_unload");

   /* free the memory alloc'd for regex */
   while (i < (fenv->len / sizeof(struct filter_op)) ) {
      /* search for func regex and pcre */
      if(fop[i].opcode == FOP_FUNC) {
         switch(fop[i].op.func.op) {
            case FFUNC_REGEX:
               regfree(fop[i].op.func.ropt->regex);
               break;
               
            case FFUNC_PCRE:
               #ifdef HAVE_PCRE
               pcre_free(fop[i].op.func.ropt->pregex);
               pcre_free(fop[i].op.func.ropt->preg_extra);
               #endif               
               break;
         }
      }
      i++;
   }
   
   /* unmap the memory area (from file) */
   munmap(fenv->map, fenv->len + sizeof(struct filter_header)); 

   /* wipe the pointer */
   fenv->map = NULL;
   fenv->chain = NULL;
   fenv->len = 0;
}


/*
 * replace relative offset to real address in the strings fields
 */
static void reconstruct_strings(struct filter_env *fenv, struct filter_header *fh)
{
   size_t i = 0;
   struct filter_op *fop = fenv->chain;
     
   /* parse all the instruction */ 
   while (i < (fenv->len / sizeof(struct filter_op)) ) {
         
      /* 
       * the real address for a string is the base of the mmap'd file
       * plus the base of the data segment plus the offset in the field
       */
      switch(fop[i].opcode) {
         case FOP_FUNC:
            if (fop[i].op.func.slen)
               fop[i].op.func.string = (char *)(fenv->map + fh->data + (int)fop[i].op.func.string);
            if (fop[i].op.func.rlen)
               fop[i].op.func.replace = (char *)(fenv->map + fh->data + (int)fop[i].op.func.replace);
            break;
            
         case FOP_TEST:
            if (fop[i].op.test.slen)
               fop[i].op.test.string = (char *)(fenv->map + fh->data + (int)fop[i].op.test.string);
            break;
         
         case FOP_ASSIGN:
            if (fop[i].op.assign.slen)
               fop[i].op.assign.string = (char *)(fenv->map + fh->data + (int)fop[i].op.assign.string);
            break;
      }
      
      i++;
   }  
   
}

/*
 * compile the regex of a filter_op
 */
static int compile_regex(struct filter_env *fenv, struct filter_header *fh)
{
   size_t i = 0;
   struct filter_op *fop = fenv->chain;
   char errbuf[100];
   int err;
#ifdef HAVE_PCRE
   const char *perrbuf = NULL;
#endif
     
   /* parse all the instruction */ 
   while (i < (fenv->len / sizeof(struct filter_op)) ) {
      
      /* search for func regex and pcre */
      if(fop[i].opcode == FOP_FUNC) {
         switch(fop[i].op.func.op) {
            case FFUNC_REGEX:

               SAFE_CALLOC(fop[i].op.func.ropt->regex, 1, sizeof(regex_t));
   
               /* prepare the regex */
               err = regcomp(fop[i].op.func.ropt->regex, fop[i].op.func.string, REG_EXTENDED | REG_NOSUB | REG_ICASE );
               if (err) {
                  regerror(err, fop[i].op.func.ropt->regex, errbuf, sizeof(errbuf));
                  FATAL_MSG("filter engine: %s", errbuf);
               } 
               break;
               
            case FFUNC_PCRE:
               #ifdef HAVE_PCRE

               /* prepare the regex (with default option) */
               fop[i].op.func.ropt->pregex = pcre_compile(fop[i].op.func.string, 0, &perrbuf, &err, NULL );
               if (fop[i].op.func.ropt->pregex == NULL)
                  FATAL_MSG("filter engine: %s\n", perrbuf);
  
               /* optimize the pcre */
               fop[i].op.func.ropt->preg_extra = pcre_study(fop[i].op.func.ropt->pregex, 0, &perrbuf);
               if (perrbuf != NULL)
                  FATAL_MSG("filter engine: %s\n", perrbuf);
               
               #endif               
               break;
         }
      }
      i++;
   } 

   return ESUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

