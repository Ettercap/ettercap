
#ifndef EC_FINGERPRINT_H
#define EC_FINGERPRINT_H

extern int fingerprint_init(void);
extern char * fingerprint_search(char *m);
extern void fingerprint_default(char *finger);
extern void fingerprint_push(char *finger, int param, int value);
extern u_char TTL_PREDICTOR(u_char x);

/*
 *  The fingerprint database has the following structure:                  
 *                                                                         
 *  WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS                                       
 *                                                                         
 *  WWWW: 4 digit hex field indicating the TCP Window Size                 
 *  MSS : 4 digit hex field indicating the TCP Option Maximum Segment Size 
 *        if omitted in the packet or unknown it is "_MSS"                 
 *  TTL : 2 digit hex field indicating the IP Time To Live                 
 *  WS  : 2 digit hex field indicating the TCP Option Window Scale         
 *        if omitted in the packet or unknown it is "WS"                   
 *  S   : 1 digit field indicating if the TCP Option SACK permitted is true
 *  N   : 1 digit field indicating if the TCP Options contain a NOP        
 *  D   : 1 digit field indicating if the IP Don't Fragment flag is set    
 *  T   : 1 digit field indicating if the TCP Timestamp is present         
 *  F   : 1 digit ascii field indicating the flag of the packet            
 *        S = SYN                                                          
 *        A = SYN + ACK                                                    
 *  LEN : 2 digit hex field indicating the length of the packet            
 *        if irrilevant or unknown it is "LT"                              
 *  OS  : an ascii string representing the OS                              
 */


enum {
   FINGER_LEN = 28,
   OS_LEN     = 60,
   FINGER_WINDOW     = 1,
   FINGER_MSS        = 2,
   FINGER_TTL        = 3,
   FINGER_WS         = 4,
   FINGER_SACK       = 5,
   FINGER_NOP        = 6,
   FINGER_DF         = 7,
   FINGER_TIMESTAMP  = 8,
   FINGER_TCPFLAG    = 9,
   FINGER_LT         = 10,
};

/* 
 * the structure for passive information
 * carried by PO
 */

struct passive_info {
   char fingerprint[FINGER_LEN+1];
   char flags;
      #define FP_HOST_LOCAL      0
      #define FP_HOST_NONLOCAL   1
      #define FP_GATEWAY         1<<1
};


#endif

/* EOF */

// vim:ts=3:expandtab

