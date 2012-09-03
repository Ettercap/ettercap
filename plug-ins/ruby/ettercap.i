%module ettercap
/*
  SWIG doesn't know what a u_int8 or int8 is, for that matter. So, we have
  to set up the typedefs so that it knows what to preprocess these into. 
  This allows us to have full access to the data from our dynamic environments.
*/
typedef unsigned char u_int8_t;
typedef unsigned char u_char;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long int u_int64_t;

typedef char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef long int int64_t;

typedef int8_t    int8;
typedef int16_t   int16;
typedef int32_t   int32;
typedef int64_t   int64;

typedef u_int8_t   u_int8;
typedef u_int16_t  u_int16;
typedef u_int32_t  u_int32;
typedef u_int64_t  u_int64;

%include <typemaps.i>

%{
#include "ec.h"
#include "ec_ui.h"
#include "ec_packet.h"
#include "ec_inet.h"
#include "ec_fingerprint.h"
%}
%include "ec.h"
%include "ec_ui.h"
%include "ec_packet.h"
%include "ec_queue.h"
%include "ec_inet.h"
%include "ec_fingerprint.h"

