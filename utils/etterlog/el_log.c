/*
    etterlog -- read the logfile

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

#include <el.h>
#include <ec_log.h>

void open_log(char *file);
int get_header(struct log_global_header *hdr);
int get_packet(struct log_header_packet *pck, u_char **buf);
int get_info(struct log_header_info *inf, struct dissector_info *buf);
static int put_header(gzFile fd, struct log_global_header *hdr);
static int put_packet(gzFile fd, struct log_header_packet *pck, u_char *buf);
static int put_info(gzFile fd, struct log_header_info *inf, struct dissector_info *buf);
void concatenate(int argc, char **argv);
static void dump_file(gzFile fd, struct log_global_header *hdr);

/*******************************************/

/* 
 * open the logfile, then drop the privs
 */

void open_log(char *file)
{
   int zerr;
   
   EL_GBL_LOGFILE = strdup(file);
   EL_GBL_LOG_FD = gzopen(file, "rb");
   if(EL_GBL_LOG_FD == Z_NULL)
      FATAL_ERROR("Cannot read the log file, please ensure you have enough permissions to read %s: error %s", file, gzerror(EL_GBL_LOG_FD, &zerr));
}

/*
 * returns the global header 
 */

int get_header(struct log_global_header *hdr)
{
   int c;

   c = gzread(EL_GBL_LOG_FD, hdr, sizeof(struct log_global_header));

   if (c != sizeof(struct log_global_header))
      return -E_INVALID;
   
   /* convert to host order */
   
   hdr->magic = ntohs(hdr->magic);
   
   if (hdr->magic != EC_LOG_MAGIC)
      return -E_INVALID;
   
   hdr->first_header = ntohs(hdr->first_header);
   gzseek(EL_GBL_LOG_FD, hdr->first_header, SEEK_SET);
  
   /* adjust the timestamp */
   hdr->tv.tv_sec = ntohl(hdr->tv.tv_sec);
   hdr->tv.tv_usec = ntohl(hdr->tv.tv_usec);
   
   hdr->type = ntohl(hdr->type);
   
   return E_SUCCESS;
}

/*
 * store the header in a file
 */
static int put_header(gzFile fd, struct log_global_header *hdr)
{
   int c;

   /* convert to network order */
   hdr->magic = htons(hdr->magic);
   hdr->first_header = htons(hdr->first_header);
   hdr->tv.tv_sec = htonl(hdr->tv.tv_sec);
   hdr->tv.tv_usec = htonl(hdr->tv.tv_usec);
   hdr->type = htonl(hdr->type);
   
   c = gzwrite(fd, hdr, sizeof(struct log_global_header));
   if (c != sizeof(struct log_global_header))
      FATAL_ERROR("Cannot write output file");
   
   /* convert to host order */
   hdr->magic = ntohs(hdr->magic);
   hdr->first_header = ntohs(hdr->first_header);
   hdr->tv.tv_sec = ntohl(hdr->tv.tv_sec);
   hdr->tv.tv_usec = ntohl(hdr->tv.tv_usec);
   hdr->type = ntohl(hdr->type);
   
   return E_SUCCESS;
}


/*
 * read the header of a packet
 * and return the data in the buf
 */
int get_packet(struct log_header_packet *pck, u_char **buf)
{
   int c;

   c = gzread(EL_GBL_LOG_FD, pck, sizeof(struct log_header_packet));

   if (c != sizeof(struct log_header_packet))
      return -E_INVALID;
   
   pck->len = ntohl(pck->len);
  
   /* adjust the timestamp */
   pck->tv.tv_sec = ntohl(pck->tv.tv_sec);
   pck->tv.tv_usec = ntohl(pck->tv.tv_usec);
 
   /* allocate the memory for the buffer */
   SAFE_CALLOC(*buf, pck->len, sizeof(u_char));

   /* copy the data of the packet */
   c = gzread(EL_GBL_LOG_FD, *buf, pck->len);
   
   if ((size_t)c != pck->len)
      return -E_INVALID;
   
   return E_SUCCESS;
}

/*
 * store a packet into a file
 */
static int put_packet(gzFile fd, struct log_header_packet *pck, u_char *buf)
{
   int c;
   
   pck->len = htonl(pck->len);
   pck->tv.tv_sec = htonl(pck->tv.tv_sec);
   pck->tv.tv_usec = htonl(pck->tv.tv_usec);

   c = gzwrite(fd, pck, sizeof(struct log_header_packet));
   if (c != sizeof(struct log_header_packet))
      return -E_INVALID;
   
   pck->len = ntohl(pck->len);
   pck->tv.tv_sec = ntohl(pck->tv.tv_sec);
   pck->tv.tv_usec = ntohl(pck->tv.tv_usec);

   /* copy the data of the packet */
   c = gzwrite(fd, buf, pck->len);
   if ((size_t)c != pck->len)
      return -E_INVALID;
   
   return E_SUCCESS;
}

/*
 * read the header for the info and
 * return the user, pass ecc in buf
 */
int get_info(struct log_header_info *inf, struct dissector_info *buf)
{
   int c;

   /* get the whole header */
   c = gzread(EL_GBL_LOG_FD, inf, sizeof(struct log_header_info));

   /* truncated ? */
   if (c != sizeof(struct log_header_info))
      return -E_INVALID;

   /* adjust the variable lengths */
   inf->var.user_len = ntohs(inf->var.user_len);
   inf->var.pass_len = ntohs(inf->var.pass_len);
   inf->var.info_len = ntohs(inf->var.info_len);
   inf->var.banner_len = ntohs(inf->var.banner_len);

   /* 
    * get the dissectors info
    *
    * we can deal only with associated user and pass,
    * so there must be present all of them
    */

   if (inf->var.user_len) {
      SAFE_CALLOC(buf->user, inf->var.user_len + 1, sizeof(char));
      
      c = gzread(EL_GBL_LOG_FD, buf->user, inf->var.user_len);
      if (c != inf->var.user_len)
         return -E_INVALID;
   }
   
   if (inf->var.pass_len) {
      SAFE_CALLOC(buf->pass, inf->var.pass_len + 1, sizeof(char));
      
      c = gzread(EL_GBL_LOG_FD, buf->pass, inf->var.pass_len);
      if (c != inf->var.pass_len)
         return -E_INVALID;
   }
   
   if (inf->var.info_len) {
      SAFE_CALLOC(buf->info, inf->var.info_len + 1, sizeof(char));
      
      c = gzread(EL_GBL_LOG_FD, buf->info, inf->var.info_len);
      if (c != inf->var.info_len)
         return -E_INVALID;
   }
   
   if (inf->var.banner_len) {
      SAFE_CALLOC(buf->banner, inf->var.banner_len + 1, sizeof(char));
      
      c = gzread(EL_GBL_LOG_FD, buf->banner, inf->var.banner_len);
      if (c != inf->var.banner_len)
         return -E_INVALID;
   }

   /*
    * sanity check for ip_addr struct
    */
   switch (ntohs(inf->L3_addr.addr_type)) {
      case AF_INET:
         if (ntohs(inf->L3_addr.addr_len) != IP_ADDR_LEN)
            return -E_INVALID;
         break;
      case AF_INET6:
         if (ntohs(inf->L3_addr.addr_len) != IP6_ADDR_LEN)
            return -E_INVALID;
         break;
      default:
         return -E_INVALID;
   }

   /* if client IP address has been set otherwise skip */
   if (!ip_addr_is_zero(&inf->client)) {
      switch (ntohs(inf->client.addr_type)) {
         case AF_INET:
            if (ntohs(inf->client.addr_len) != IP_ADDR_LEN)
               return -E_INVALID;
            break;
         case AF_INET6:
            if (ntohs(inf->client.addr_len) != IP6_ADDR_LEN)
               return -E_INVALID;
            break;
         default:
            return -E_INVALID;
      }
   }


   return E_SUCCESS; 
}

/*
 * store a info struct into a file 
 */
static int put_info(gzFile fd, struct log_header_info *inf, struct dissector_info *buf)
{
   int c;

   /* adjust the variable lengths */
   inf->var.user_len = htons(inf->var.user_len);
   inf->var.pass_len = htons(inf->var.pass_len);
   inf->var.info_len = htons(inf->var.info_len);
   inf->var.banner_len = htons(inf->var.banner_len);
   
   /* write the header */
   c = gzwrite(fd, inf, sizeof(struct log_header_info));
   if (c != sizeof(struct log_header_info))
      return -E_INVALID;

   /* reconvert for internal use */
   inf->var.user_len = ntohs(inf->var.user_len);
   inf->var.pass_len = ntohs(inf->var.pass_len);
   inf->var.info_len = ntohs(inf->var.info_len);
   inf->var.banner_len = ntohs(inf->var.banner_len);

   /* write the data */
   if (inf->var.user_len) {
      c = gzwrite(fd, buf->user, inf->var.user_len);
      if (c != inf->var.user_len)
         return -E_INVALID;
   }
   
   if (inf->var.pass_len) {
      c = gzwrite(fd, buf->pass, inf->var.pass_len);
      if (c != inf->var.pass_len)
         return -E_INVALID;
   }
   
   if (inf->var.info_len) {
      c = gzwrite(fd, buf->info, inf->var.info_len);
      if (c != inf->var.info_len)
         return -E_INVALID;
   }
   
   if (inf->var.banner_len) {
      c = gzwrite(fd, buf->banner, inf->var.banner_len);
      if (c != inf->var.banner_len)
         return -E_INVALID;
   }
   
   return E_SUCCESS; 
}

/*
 * concatenate two (or more) files into one single file 
 */
void concatenate(int argc, char **argv)
{
   int zerr;
   gzFile fd;
   struct log_global_header hdr, tmp;

   memset(&hdr, 0, sizeof(struct log_global_header));

   /* open the output file for writing */
   fd = gzopen(EL_GBL_LOGFILE, "wb");
   ON_ERROR(fd, NULL, "%s", gzerror(fd, &zerr));

   /* 
    * use EL_GBL_LOG_FD here so the get_header function
    * will use this file 
    */
   EL_GBL_LOG_FD = gzopen(argv[argc], "rb");
   ON_ERROR(EL_GBL_LOG_FD, NULL, "%s", gzerror(EL_GBL_LOG_FD, &zerr));
   
   /* get the file header */
   if (get_header(&hdr) != E_SUCCESS)
      FATAL_ERROR("Invalid log file (%s)", argv[argc]);

   /* write the header */
   put_header(fd, &hdr);
      
   USER_MSG("Concatenating file [%s]", argv[argc]);
   
   /* copy the first file into the output */
   dump_file(fd, &hdr);
     
   /* move the pointer to the next file */
   argc++;
   
   /* cicle thru the file list */
   while(argv[argc] != NULL) {
   
      EL_GBL_LOG_FD = gzopen(argv[argc], "rb");
      ON_ERROR(EL_GBL_LOG_FD, NULL, "%s", gzerror(EL_GBL_LOG_FD, &zerr));
   
      /* get the file header */
      if (get_header(&tmp) != E_SUCCESS)
         FATAL_ERROR("Invalid log file (%s)", argv[argc]);
     
      /* check if the files are compatible */
      if (hdr.type != tmp.type)
         FATAL_ERROR("Cannot concatenate different type of file");

      USER_MSG("Concatenating file [%s]", argv[argc]);
      
      /* concatenate this file */
      dump_file(fd, &tmp);

      gzclose(EL_GBL_LOG_FD);
      argc++;
   }

   gzclose(fd);

   USER_MSG("\nAll files concatenated into: %s\n\n", EL_GBL_LOGFILE);

   el_exit(0);
}


/*
 * dump the file into the fd
 */
static void dump_file(gzFile fd, struct log_global_header *hdr)
{
   struct log_header_packet pck;
   struct log_header_info inf;
   struct dissector_info infbuf;
   u_char *pckbuf;
   int count = 0;

   /* loop until EOF */
   LOOP {
      switch (hdr->type) {
         case LOG_INFO:
            if (get_info(&inf, &infbuf) != E_SUCCESS) {
               USER_MSG("\n");
               return;
            }
            /* write the info */
            put_info(fd, &inf, &infbuf);
            SAFE_FREE(infbuf.user);
            SAFE_FREE(infbuf.pass);
            SAFE_FREE(infbuf.info);
            SAFE_FREE(infbuf.banner);

            break;

         case LOG_PACKET:
            if (get_packet(&pck, &pckbuf) != E_SUCCESS) {
               USER_MSG("\n");
               return;
            }
            /* write the data */
            put_packet(fd, &pck, pckbuf);
            SAFE_FREE(pckbuf);
            break;
            
         default:
            FATAL_ERROR("Unknown log type");
            break;
      }
      
      /* a dot every 10 packets */
      if (count++ % 10 == 0) {
         USER_MSG(".");
         fflush(stdout);
      }
   }

}


/* EOF */

// vim:ts=3:expandtab

