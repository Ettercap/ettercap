
/* $Id: ec_capture.h,v 1.5 2004/02/27 11:06:28 alor Exp $ */

#ifndef EC_CAPTURE_H
#define EC_CAPTURE_H

#include <ec_threads.h>

extern void capture_init(void);
extern void capture_close(void);
extern EC_THREAD_FUNC(capture);
extern EC_THREAD_FUNC(capture_bridge);

extern void get_hw_info(void);
extern int is_pcap_file(char *file, char *errbuf);

#define FUNC_ALIGNER(func) int func(void)
#define FUNC_ALIGNER_PTR(func) int (*func)(void)

extern void add_aligner(int dlt, int (*aligner)(void));

#endif

/* EOF */

// vim:ts=3:expandtab

