/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Milter support */

#include "exim.h"
#ifdef EXPERIMENTAL_MILTER

enum {
  MILTER_ACCEPT,
  MILTER_REJECT,
  MILTER_TEMPFAIL,
  MILTER_UNKNOWN
};

int milter_condition(uschar *arg, int where)
{
  int rc;
  log_write(0, LOG_MAIN, __FILE__": \"milter = %s\" called where=%d", arg, where);

#if 1
  rc = MILTER_UNKNOWN;
  milter_message = "test message";
#else
#endif

  switch (rc) {
  case MILTER_ACCEPT:
    milter_result = "accept";
    return OK;
  case MILTER_REJECT:
    milter_result = "deny";
    return OK;
  case MILTER_TEMPFAIL:
    milter_result = "defer";
    return OK;
  default:
    milter_result = "error";
    return ERROR;
  }
}

#endif

/*
  Local Variables:
  c-basic-offset: 2
  End:
*/
