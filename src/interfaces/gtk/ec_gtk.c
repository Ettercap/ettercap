/*
    ettercap -- GTK GUI

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

    $Id: ec_gtk.c,v 1.1 2004/02/22 12:00:55 alor Exp $
*/

#include <ec.h>


/* globals */

/* proto */

void set_gtk_interface(void);
void gtk_interface(void);

static void gtk_init(void);
static void gtk_cleanup(void);
static void gtk_msg(const char *msg);
static void gtk_error(const char *msg);
static void gtk_fatal_error(const char *msg);
static void gtk_input(const char *title, char *input, size_t n);
static void gtk_progress(char *title, int value, int max);


/*******************************************/


void set_gtk_interface(void)
{
   struct ui_ops ops;

   /* wipe the struct */
   memset(&ops, 0, sizeof(ops));

   /* register the functions */
   ops.init = &gtk_init;
   ops.start = &gtk_interface;
   ops.cleanup = &gtk_cleanup;
   ops.msg = &gtk_msg;
   ops.error = &gtk_error;
   ops.fatal_error = &gtk_fatal_error;
   ops.input = &gtk_input;
   ops.progress = &gtk_progress;
   ops.type = UI_GTK;
   
   ui_register(&ops);
   
   NOT_IMPLEMENTED();
}


/*
 * set the terminal as non blocking 
 */
static void gtk_init(void)
{
   DEBUG_MSG("gtk_init");

}

/*
 * reset to the previous state
 */
static void gtk_cleanup(void)
{
   DEBUG_MSG("gtk_cleanup");

}

/*
 * print a USER_MSG() extracting it from the queue
 */
static void gtk_msg(const char *msg)
{

}

/*
 * print an error
 */
static void gtk_error(const char *msg)
{
   DEBUG_MSG("gtk_error: %s", msg);
}


/*
 * handle a fatal error and exit
 */
static void gtk_fatal_error(const char *msg)
{

   clean_exit(-1);
}


/*
 * get an input from the user blocking
 */
static void gtk_input(const char *title, char *input, size_t n)
{
}

/* 
 * implement the progress bar 
 */
static void gtk_progress(char *title, int value, int max)
{
}


/* the interface */

void gtk_interface(void)
{
   DEBUG_MSG("gtk_interface");
}


/* EOF */

// vim:ts=3:expandtab

