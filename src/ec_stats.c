/*
    ettercap -- statistics collection module

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

    $Id: ec_stats.c,v 1.6 2003/10/29 20:41:07 alor Exp $
*/

#include <ec.h>
#include <ec_stats.h>

#include <sys/time.h>

/* protos */

u_int32 stats_queue_add(void);
u_int32 stats_queue_del(void);

void stats_half_start(struct half_stats *hs);
void stats_half_end(struct half_stats *hs, u_int32 len);

/************************************************/

u_int32 stats_queue_add(void)
{
   /* increment the counter */
   GBL_STATS->queue_curr++;
   
   /* check if the max has to be updated */
   if (GBL_STATS->queue_curr > GBL_STATS->queue_max)
      GBL_STATS->queue_max = GBL_STATS->queue_curr;

   return GBL_STATS->queue_curr;
}

u_int32 stats_queue_del(void)
{
   /* decrement the current counter */
   GBL_STATS->queue_curr--;

   return GBL_STATS->queue_curr;
}

/*
 * gets the timeval initial value
 * to calculate the processing time
 */

void stats_half_start(struct half_stats *hs)
{
   /* get the time */
   gettimeofday(&hs->ts, 0);
}

/*
 * update the packet (num and size) couters
 * and get the time diff to calculate the 
 * rate
 */
void stats_half_end(struct half_stats *hs, u_int32 len)
{
   struct timeval diff;
   float time; 
   float ttime;
   float ptime;

   /* get the time */
   gettimeofday(&hs->te, 0);

   time_sub(&hs->te, &hs->ts, &diff);
   time_add(&hs->ttot, &diff, &hs->ttot);
   time_add(&hs->tpar, &diff, &hs->tpar);

   /* calculate the rate (packet/time) */
   time = diff.tv_sec + diff.tv_usec/1.0e6;
   ttime = hs->ttot.tv_sec + hs->ttot.tv_usec/1.0e6;
   ptime = hs->tpar.tv_sec + hs->tpar.tv_usec/1.0e6;

   /* update the packet count */
   hs->pck_recv++;
   hs->pck_size += len;
   hs->tmp_size += len;
   
   if ( (hs->pck_recv % GBL_CONF->sampling_rate) == 0 ) {
      /* save the average and the worst sampling */
      hs->rate_adv = hs->pck_recv/ttime;
      if (hs->rate_worst > GBL_CONF->sampling_rate/ptime || hs->rate_worst == 0)
         hs->rate_worst = GBL_CONF->sampling_rate/ptime;
      
      hs->thru_adv = hs->pck_size/ttime;
      if (hs->thru_worst > hs->tmp_size/ptime || hs->thru_worst == 0)
         hs->thru_worst = hs->tmp_size/ptime;

#if 1
      DEBUG_MSG("PACKET RATE: %llu [%d] [%d] -- [%d] [%d]\n", hs->pck_recv,
         hs->rate_worst, hs->rate_adv,
         hs->thru_worst, hs->thru_adv);
#endif
            
      /* reset the partial */
      memset(&hs->tpar, 0, sizeof(struct timeval));
      hs->tmp_size = 0;
   }

}

/* EOF */

// vim:ts=3:expandtab

