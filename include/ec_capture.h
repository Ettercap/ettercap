
/* $Id: ec_capture.h,v 1.3 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_CAPTURE_H
#define EC_CAPTURE_H

#include <ec_threads.h>

extern void capture_init(void);
extern void capture_close(void);
extern EC_THREAD_FUNC(capture);
extern EC_THREAD_FUNC(capture_bridge);

extern void get_hw_info(void);
#endif

/* EOF */

// vim:ts=3:expandtab

