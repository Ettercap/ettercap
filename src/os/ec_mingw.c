/*
    ettercap -- mingw specific functions

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

    $Id: ec_mingw.c,v 1.1 2004/06/27 12:51:02 alor Exp $
    
    Various functions needed for native Windows compilers (not CygWin I guess??)
    We export these (for the plugins) with a "ec_win_" prefix in order not to accidentally
    link with other symbols in some foreign lib.

    Copyright (C) G. Vanem 2003   <giva@bgnett.no>

 */

#define FD_SETSIZE  2048

#include <ec.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/timeb.h>
#include <conio.h>
#include <io.h>
#include <pcap.h>

#ifndef __inline
#define __inline
#endif

#ifndef __GNUC__
#error "You must be joking"
#endif

#undef extern

extern int ettercap_main (int, char**);  /* ec_main.c */

char pcap_version [60] = "unknown";      /* current libpcap/WinPcap doesn't have this */

static void __init get_pcap_version (void)
{
  const char *ver = pcap_lib_version();

  if (ver)
  {
    strncpy (pcap_version, ver, sizeof(pcap_version)-1);
    pcap_version [sizeof(pcap_version)-1] = '\0';
  }
}

#ifdef HAVE_GTK  /* give use back the console prompt */
int _stdcall WinMain (struct HINSTANCE__ *hInstance,
                      struct HINSTANCE__ *hPrevInstance,
                      char               *lpszCmdLine,
                      int                 nCmdShow)
{
  get_pcap_version();
  return ettercap_main (__argc, __argv);
}
#endif

u_int16 get_iface_mtu(char *iface)
{
  (void)iface;
  return 1514;
}

void disable_ip_forward (void)
{
  DEBUG_MSG ("disable_ip_forward (no-op\n");
}

/*
 * No fork() in Windows, just beep
 */
void set_daemon_interface (void)
{
  _putch ('\a');
}

int ec_win_gettimeofday (struct timeval *tv, struct timezone *tz)
{
  struct _timeb tb;

  if (!tv)
     return (-1);

  _ftime (&tb);
  tv->tv_sec  = tb.time;
  tv->tv_usec = tb.millitm * 1000 + 500;
  if (tz)
  {
    tz->tz_minuteswest = -60 * _timezone;
    tz->tz_dsttime = _daylight;
  }
  return (0);
}

/*
 * A poll() using select() and _kbhit()
 */
int ec_win_poll (struct pollfd *p, int num, int timeout)
{
  struct timeval tv;
  int    i, n, ret, num_fd = (num + sizeof(fd_set)-1) / sizeof(fd_set);
  fd_set read  [num_fd];
  fd_set write [num_fd];
  fd_set excpt [num_fd];

  FD_ZERO (&read);
  FD_ZERO (&write);
  FD_ZERO (&excpt);

  n = -1;
  for (i = 0; i < num; i++)
  {
    if (p[i].fd < 0)
       continue;

    if ((p[i].events & POLLIN) && i != STDIN_FILENO)
        FD_SET (p[i].fd, &read[0]);

    if ((p[i].events & POLLOUT) && i != STDOUT_FILENO)
        FD_SET (p[i].fd, &write[0]);

    if (p[i].events & POLLERR)
       FD_SET (p[i].fd, &excpt[0]);

    if (p[i].fd > n)
       n = p[i].fd;
  }

  if (n == -1)
     return (0);

  if (timeout < 0)
     ret = select (n+1, &read[0], &write[0], &excpt[0], NULL);
  else
  {
    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = 1000 * (timeout % 1000);
    ret = select (n+1, &read[0], &write[0], &excpt[0], &tv);
  }

  for (i = 0; ret >= 0 && i < num; i++)
  {
    p[i].revents = 0;
    if (FD_ISSET (p[i].fd, &read[0]))
       p[i].revents |= POLLIN;
    if (FD_ISSET (p[i].fd, &write[0]))
       p[i].revents |= POLLOUT;
    if (FD_ISSET (p[i].fd, &excpt[0]))
       p[i].revents |= POLLERR;
  }

  if ((p[STDIN_FILENO].events & POLLIN) && num >= STDIN_FILENO && _kbhit())
  {
    p [STDIN_FILENO].revents = POLLIN;
    ret++;
  }
  if ((p[STDOUT_FILENO].events & POLLOUT) && num >= STDOUT_FILENO && isatty(STDOUT_FILENO) >= 0)
  {
    p [STDOUT_FILENO].revents = POLLOUT;
    ret++;
  }
  return (ret);
}

/*
 * For consistent and nice looks, replace '\\' with '/'.
 * All (?) Windows core functions and libc handles this fine.
 */
static char *slashify (char *path)
{
  char *p;
  for (p = strchr(path,'\\'); p && *p; p = strchr(p,'\\'))
      *p++ = '/';
  return (path);
}

/*
 * Return current user's home directory. Try:
 *   - %HOME%
 *   - %APPDATA%
 *   - %USERPROFILE%\\Application Data
 *   - else EC's dir.
 *
 * Not used yet.
 */
const char *ec_win_get_user_dir (void)
{
  static char path[MAX_PATH] = "";
  char  *home;

  if (path[0])
     return (path);

  home = getenv ("HOME");
  if (home)
     strncpy (path, home, sizeof(path)-1);
  else
  {
    home = getenv ("APPDATA");         /* Win-9x/ME */
    if (home)
       strncpy (path, home, sizeof(path)-1);
    else
    {
      home = getenv ("USERPROFILE");   /* Win-2K/XP */
      if (home)
           snprintf (path, sizeof(path)-1, "%s\\Application Data", home);
      else strncpy (path, ec_win_get_ec_dir(), sizeof(path)-1);
    }
  }
  path [sizeof(path)-1] = '\0';
  return slashify (path);
}

/*
 * Return directory of running program.
 */
const char *ec_win_get_ec_dir (void)
{
  static char path[MAX_PATH] = "c:\\";
  char *slash;

  if (GetModuleFileName(NULL,path,sizeof(path)) &&
      (slash = strrchr(path,'\\')) != NULL)
     *slash = '\0';
  return slashify (path);
}

/*
 * Return name of a signal
 */
const char *ec_win_strsignal (int signo)
{
  static char buf [20];

  switch (signo)
  {
    case 0:
         return ("None");
#ifdef SIGINT
    case SIGINT:
         return ("SIGINT");
#endif
#ifdef SIGABRT
    case SIGABRT:
         return ("SIGABRT");
#endif
#ifdef SIGFPE
    case SIGFPE:
         return ("SIGFPE");
#endif
#ifdef SIGILL
    case SIGILL:
         return ("SIGILL");
#endif
#ifdef SIGSEGV
    case SIGSEGV:
         return ("SIGSEGV");
#endif
#ifdef SIGTERM
    case SIGTERM:
         return ("SIGTERM");
#endif
#ifdef SIGALRM
    case SIGALRM:
         return ("SIGALRM");
#endif
#ifdef SIGHUP
    case SIGHUP:
         return ("SIGHUP");
#endif
#ifdef SIGKILL
    case SIGKILL:
         return ("SIGKILL");
#endif
#ifdef SIGPIPE
    case SIGPIPE:
         return ("SIGPIPE");
#endif
#ifdef SIGQUIT
    case SIGQUIT:
         return ("SIGQUIT");
#endif
#ifdef SIGUSR1
    case SIGUSR1:
         return ("SIGUSR1");
#endif
#ifdef SIGUSR2
    case SIGUSR2:
         return ("SIGUSR2");
#endif
#ifdef SIGUSR3
    case SIGUSR3:
         return ("SIGUSR3");
#endif
#ifdef SIGNOFP
    case SIGNOFP:
         return ("SIGNOFP");
#endif
#ifdef SIGTRAP
    case SIGTRAP:
         return ("SIGTRAP");
#endif
#ifdef SIGTIMR
    case SIGTIMR:
         return ("SIGTIMR");
#endif
#ifdef SIGPROF
    case SIGPROF:
         return ("SIGPROF");
#endif
#ifdef SIGSTAK
    case SIGSTAK:
         return ("SIGSTAK");
#endif
#ifdef SIGBRK
    case SIGBRK:
         return ("SIGBRK");
#endif
#ifdef SIGBUS
    case SIGBUS:
         return ("SIGBUS");
#endif
#ifdef SIGIOT
    case SIGIOT:
         return ("SIGIOT");
#endif
#ifdef SIGEMT
    case SIGEMT:
         return ("SIGEMT");
#endif
#ifdef SIGSYS
    case SIGSYS:
         return ("SIGSYS");
#endif
#ifdef SIGCHLD
    case SIGCHLD:
         return ("SIGCHLD");
#endif
#ifdef SIGPWR
    case SIGPWR:
         return ("SIGPWR");
#endif
#ifdef SIGWINCH
    case SIGWINCH:
         return ("SIGWINCH");
#endif
#ifdef SIGPOLL
    case SIGPOLL:
         return ("SIGPOLL");
#endif
#ifdef SIGCONT
    case SIGCONT:
         return ("SIGCONT");
#endif
#ifdef SIGSTOP
    case SIGSTOP:
         return ("SIGSTOP");
#endif
#ifdef SIGTSTP
    case SIGTSTP:
         return ("SIGTSTP");
#endif
#ifdef SIGTTIN
    case SIGTTIN:
         return ("SIGTTIN");
#endif
#ifdef SIGTTOU
    case SIGTTOU:
         return ("SIGTTOU");
#endif
#ifdef SIGURG
    case SIGURG:
         return ("SIGURG");
#endif
#ifdef SIGLOST
    case SIGLOST:
         return ("SIGLOST");
#endif
#ifdef SIGDIL
    case SIGDIL:
         return ("SIGDIL");
#endif
#ifdef SIGXCPU
    case SIGXCPU:
         return ("SIGXCPU");
#endif
#ifdef SIGXFSZ
    case SIGXFSZ:
         return ("SIGXFSZ");
#endif
  }
  strcpy (buf, "Unknown ");
  itoa (signo, buf+8, 10);
  return (buf);
}

/*
 * fork() related stuff
 */

int ec_win_fork(void)
{
   USER_MSG("fork() not yet supported");
   return -1;
}

/*
 * A simple mmap() emulation.
 */
struct mmap_list {
       HANDLE            os_map;
       DWORD             size;
       const void       *file_ptr;
       struct mmap_list *next;
     };

static struct mmap_list *mmap_list0 = NULL;

static __inline struct mmap_list *
lookup_mmap (const void *file_ptr, size_t size)
{
  struct mmap_list *m;

  if (!file_ptr || size == 0)
     return (NULL);

  for (m = mmap_list0; m; m = m->next)
      if (m->file_ptr == file_ptr && m->size == (DWORD)size && m->os_map)
         return (m);
  return (NULL);
}

static __inline struct mmap_list *
add_mmap_node (const void *file_ptr, const HANDLE os_map, DWORD size)
{
  struct mmap_list *m = malloc (sizeof(*m));

  if (!m)
     return (NULL);

  m->os_map   = os_map;
  m->file_ptr = file_ptr;
  m->size     = size;
  m->next     = mmap_list0;
  mmap_list0  = m;
  return (m);
}

static __inline struct mmap_list *
unlink_mmap (struct mmap_list *This)
{
  struct mmap_list *m, *prev, *next;

  for (m = prev = mmap_list0; m; prev = m, m = m->next)
  {
    if (m != This)
       continue;
    if (m == mmap_list0)
         mmap_list0 = m->next;
    else prev->next = m->next;
    next = m->next;
    free (m);
    return (next);
  }
  return (NULL);
}

void *ec_win_mmap (int fd, size_t size, int prot)
{
  HANDLE os_handle, os_map;
  void  *file_ptr;

  if (fd < 0 || size == 0 ||
      (prot & (PROT_READ|PROT_WRITE)) == 0)
  {
    errno = EINVAL;
    return (MAP_FAILED);
  }

  /* todo:
     prot 0                -> PAGE_NOACCESS
     PROT_READ             -> PAGE_READONLY
     PROT_READ|PROT_WRITE  -> PAGE_READWRITE
     PROT_WRITE            -> PAGE_WRITECOPY
  */

  os_handle = (HANDLE) _get_osfhandle (fd);
  if (!os_handle)
     return (MAP_FAILED);

  os_map = CreateFileMapping (os_handle, NULL,
                              (prot == PROT_READ) ? PAGE_READONLY : PAGE_WRITECOPY,
                              0, 0, NULL);
  if (!os_map)
     return (MAP_FAILED);

  file_ptr = MapViewOfFile (os_map, (prot == PROT_READ) ? FILE_MAP_READ : FILE_MAP_WRITE,
                            0, 0, 0);

  if (file_ptr && !add_mmap_node (file_ptr, os_map, size))
  {
    file_ptr = NULL;
    FlushViewOfFile (file_ptr, size);
    UnmapViewOfFile (file_ptr);
    CloseHandle (os_map);
  }
  DEBUG_MSG ("ec_win_mmap(): fd %d, os_map %08lX, file_ptr %08lX, size %u, prot %d\n",
             fd, (DWORD)os_map, (DWORD)file_ptr, size, prot);
  return (file_ptr);
}

int ec_win_munmap (const void *file_ptr, size_t size)
{
  struct mmap_list *m = lookup_mmap (file_ptr, size);

  if (!m)
  {
    WSASetLastError (EINVAL);
    return (-1);
  }
  FlushViewOfFile (m->file_ptr, m->size);
  UnmapViewOfFile ((void*)m->file_ptr);
  CloseHandle (m->os_map);
  unlink_mmap (m);
  return (0);
}

/*
 * BIND resolver stuff:
 *
 * Expand compressed domain name 'comp_dn' to full domain name.
 * 'msg' is a pointer to the begining of the message,
 * 'eom_orig' points to the first location after the message,
 * 'exp_dn' is a pointer to a buffer of size 'length' for the result.
 * Return size of compressed name or -1 if there was an error.
 */
#define INDIR_MASK  0xc0
#define MAXLABEL    63         /* maximum length of domain label */

static int mklower (int ch)
{
  if (isascii(ch) && isupper(ch))
     return (tolower(ch));
  return (ch);
}

/*
 * Search for expanded name from a list of previously compressed names.
 * Return the offset from msg if found or -1.
 * dnptrs is the pointer to the first name on the list,
 * not the pointer to the start of the message.
 */
static int dn_find (u_char *exp_dn, u_char *msg, u_char **dnptrs, u_char **lastdnptr)
{
  u_char **cpp;

  for (cpp = dnptrs; cpp < lastdnptr; cpp++)
  {
    u_char *dn = exp_dn;
    u_char *sp = *cpp;
    u_char *cp = *cpp;
    int     n;

    while ((n = *cp++) != 0)
    {
      /*
       * check for indirection
       */
      switch (n & INDIR_MASK)
      {
        case 0:    /* normal case, n == len */
             while (--n >= 0)
             {
               if (*dn == '.')
                  goto next;
               if (*dn == '\\')
                  dn++;
               if (mklower(*dn++) != mklower(*cp++))
                  goto next;
             }
             if ((n = *dn++) == '\0' && *cp == '\0')
                return (sp - msg);
             if (n == '.')
                continue;
             goto next;

        case INDIR_MASK:  /* indirection */
             cp = msg + (((n & 0x3f) << 8) | *cp);
             break;

        default:          /* illegal type */
             return (-1);
      }
    }
    if (*dn == '\0')
      return (sp - msg);
    next: ;
  }
  return (-1);
}

int ec_win_dn_expand (const u_char *msg, const u_char *eom_orig,
                      const u_char *comp_dn, char *exp_dn, int length)
{
  const u_char *cp;
  char *dn, *eom;
  int   n, len = -1, checked = 0;

  dn  = exp_dn;
  cp  = comp_dn;
  eom = exp_dn + length;

  /* Fetch next label in domain name
   */
  while ((n = *cp++) != 0)
  {
    /* Check for indirection */
    switch (n & INDIR_MASK)
    {
      case 0:
           if (dn != exp_dn)
           {
             if (dn >= eom)
                return (-1);
             *dn++ = '.';
           }
           if (dn+n >= eom)
              return (-1);
           checked += n + 1;
           while (--n >= 0)
           {
             int c = *cp++;
             if ((c == '.') || (c == '\\'))
             {
               if (dn + n + 2 >= eom)
                  return (-1);
               *dn++ = '\\';
             }
             *dn++ = c;
             if (cp >= eom_orig)  /* out of range */
                return (-1);
           }
           break;

      case INDIR_MASK:
           if (len < 0)
              len = cp - comp_dn + 1;
           cp = msg + (((n & 0x3f) << 8) | (*cp & 0xff));
           if (cp < msg || cp >= eom_orig)  /* out of range */
              return (-1);
           checked += 2;
           /*
            * Check for loops in the compressed name;
            * if we've looked at the whole message,
            * there must be a loop.
            */
           if (checked >= eom_orig - msg)
              return (-1);
           break;

      default:
           return (-1);   /* flag error */
    }
  }

  *dn = '\0';
  {
    int c;
    for (dn = exp_dn; (c = *dn) != '\0'; dn++)
        if (isascii(c) && isspace(c))
           return (-1);
  }
  if (len < 0)
     len = cp - comp_dn;
  return (len);
}

/*
 * Compress domain name 'exp_dn' into 'comp_dn'.
 * Return the size of the compressed name or -1.
 * 'length' is the size of the array pointed to by 'comp_dn'.
 * 'dnptrs' is a list of pointers to previous compressed names. dnptrs[0]
 * is a pointer to the beginning of the message. The list ends with NULL.
 * 'lastdnptr' is a pointer to the end of the arrary pointed to
 * by 'dnptrs'. Side effect is to update the list of pointers for
 * labels inserted into the message as we compress the name.
 * If 'dnptr' is NULL, we don't try to compress names. If 'lastdnptr'
 * is NULL, we don't update the list.
 */
int dn_comp (const char *exp_dn, u_char *comp_dn, int length,
             u_char **dnptrs, u_char **lastdnptr)
{
  u_char  *cp, *dn;
  u_char **cpp, **lpp, *eob;
  u_char  *msg;
  u_char  *sp = NULL;
  int      c, l = 0;

  dn  = (u_char *)exp_dn;
  cp  = comp_dn;
  eob = cp + length;
  lpp = cpp = NULL;
  if (dnptrs)
  {
    if ((msg = *dnptrs++) != NULL)
    {
      for (cpp = dnptrs; *cpp; cpp++)
          ;
      lpp = cpp;  /* end of list to search */
    }
  }
  else
    msg = NULL;

  for (c = *dn++; c != '\0'; )
  {
    /* look to see if we can use pointers */
    if (msg)
    {
      if ((l = dn_find (dn-1, msg, dnptrs, lpp)) >= 0)
      {
        if (cp+1 >= eob)
           return (-1);
        *cp++ = (l >> 8) | INDIR_MASK;
        *cp++ = l % 256;
        return (cp - comp_dn);
      }
      /* not found, save it */
      if (lastdnptr && cpp < lastdnptr-1)
      {
        *cpp++ = cp;
        *cpp = NULL;
      }
    }
    sp = cp++;  /* save ptr to length byte */
    do
    {
      if (c == '.')
      {
        c = *dn++;
        break;
      }
      if (c == '\\')
      {
        if ((c = *dn++) == '\0')
           break;
      }
      if (cp >= eob)
      {
        if (msg)
           *lpp = NULL;
        return (-1);
      }
      *cp++ = c;
    }
    while ((c = *dn++) != '\0');

    /* catch trailing '.'s but not '..' */
    if ((l = cp - sp - 1) == 0 && c == '\0')
    {
      cp--;
      break;
    }
    if (l <= 0 || l > MAXLABEL)
    {
      if (msg)
         *lpp = NULL;
      return (-1);
    }
    *sp = l;
  }
  if (cp >= eob)
  {
    if (msg)
       *lpp = NULL;
    return (-1);
  }
  *cp++ = '\0';
  return (cp - comp_dn);
}


/*
 * dlopen() emulation (not exported)
 */
static char *last_func;
static DWORD last_error;

void *ec_win_dlopen (const char *dll_name, int flags _U_)
{
  void *rc;

  last_func = "ec_win_dlopen";
  rc = (void*) LoadLibrary (dll_name);
  if (rc)
       last_error = 0;
  else last_error = GetLastError();
  return (rc);
}

void *ec_win_dlsym (const void *dll_handle, const char *func_name)
{
  void *rc;

  last_func = "ec_win_dlsym";
  rc = (void*) GetProcAddress ((HINSTANCE)dll_handle, func_name);
  if (rc)
       last_error = 0;
  else last_error = GetLastError();
  return (rc);
}

void ec_win_dlclose (const void *dll_handle)
{
  last_func = "ec_win_dlclose";
  if (FreeLibrary((HMODULE)dll_handle))
       last_error = 0;
  else last_error = GetLastError();
}

const char *ec_win_dlerror (void)
{
  static char errbuf[1024];
  char  *p = errbuf;
  DWORD  lang  = MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT);
  DWORD  flags = FORMAT_MESSAGE_FROM_SYSTEM |
                 FORMAT_MESSAGE_IGNORE_INSERTS |
                 FORMAT_MESSAGE_MAX_WIDTH_MASK;

  p += snprintf (p, sizeof(errbuf)-1, "%s(): %lu: ", last_func, last_error);
  if (!FormatMessage(flags, NULL, last_error, lang, p,
                     sizeof(errbuf) - (p-errbuf), NULL))
     strcat (p, "Unknown error");

  /* strip trailing '\r\n' or '\n'. */
  if ((p = strrchr(errbuf,'\n')) != NULL && (p - errbuf) >= 2)
     *p = '\0';
  if ((p = strrchr(errbuf,'\r')) != NULL && (p - errbuf) >= 1)
     *p = '\0';
  return (errbuf);
}
