/*
    ettercap -- daemonization (no GUI)

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/interfaces/daemon/ec_daemon.c,v 1.5 2003/03/29 20:13:43 alor Exp $
*/

#include <ec.h>
#include <ec_ui.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

/* proto */

void set_daemon_interface(void);
void daemon_interface(void);
static void daemon_init(void);
static void daemon_cleanup(void);
static void daemon_msg(const char *msg);
static void daemon_progress(int value, int max);
static void daemonize(void);

/*******************************************/


void set_daemon_interface(void)
{
   struct ui_ops ops;

   ops.init = &daemon_init;
   ops.start = &daemon_interface;
   ops.cleanup = &daemon_cleanup;
   ops.msg = &daemon_msg;
   ops.progress = &daemon_progress;
   ops.type = UI_DAEMONIZE;
   
   ui_register(&ops);
   
}

/* 
 * initialization
 */

static void daemon_init(void)
{
   /* daemonize ettercap */
   daemonize();
}


/*
 * open a file and dup2 it to in, out and err.
 *
 * in this way the user can track errors verified during 
 * daemonization
 */

static void daemon_cleanup(void)
{
   int fd;
   
   fd = open("/tmp/ettercap_demonized.log", O_CREAT|O_TRUNC|O_WRONLY, 0600);
   ON_ERROR(fd, -1, "Can't open exit file");

   /* redirect in, out and err to fd */
   dup2(fd, STDIN_FILENO);
   dup2(fd, STDOUT_FILENO);
   dup2(fd, STDERR_FILENO);

   fprintf(stdout, "\nettercap errors during daemonization are reported below:\n\n");
}


/* 
 * implement the progress bar (none for daemon) 
 */

static void daemon_progress(int value, int max)
{
   return;                    
}

/* discard the messages */
static void daemon_msg(const char *msg)
{
   DEBUG_MSG("%s", msg);
   return;
}

/* the interface */

void daemon_interface(void)
{
  
   DEBUG_MSG("daemon_interface");

   /* discard the messages */
   LOOP {
      sleep(1); 
      ui_msg_flush(10);
   }
  
   /* NOT REACHED */
   
}

/*
 * set the terminal as non blocking 
 */

static void daemonize(void)
{
#ifdef HAVE_DAEMON
   int ret;

   DEBUG_MSG("daemonize: (daemon)");
   
   fprintf(stdout, "Daemonizing %s...\n\n", GBL_PROGRAM);
   
   /* 
    * daemonze the process.
    * keep the current directory
    * close stdin, out and err
    */
   ret = daemon(1, 0);
   ON_ERROR(ret, -1, "Can't demonize %s", GBL_PROGRAM);
   
#else
   int fd;
   pid_t pid;
  
   DEBUG_MSG("daemonize: (manual)");

   fprintf(stdout, "Daemonizing %s...\n\n", GBL_PROGRAM);
   
   if((signal(SIGTTOU, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((signal(SIGTTIN, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((signal(SIGTSTP, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((signal(SIGHUP, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   pid = fork();
   
   if( pid < 0)
      ERROR_MSG("fork()");
   
   /* kill the father and detach the son */
   if ( pid != 0)
      exit(0);

   if(setsid() == -1)
      ERROR_MSG("setsid(): cannot set the session id");

   fd = open("/dev/null", O_RDWR);
   ON_ERROR(fd, -1, "Can't open /dev/null");

   /* redirect in, out and err to /dev/null */
   dup2(fd, STDIN_FILENO);
   dup2(fd, STDOUT_FILENO);
   dup2(fd, STDERR_FILENO);
   
   close(fd);
   
#endif
}

/* EOF */

// vim:ts=3:expandtab

