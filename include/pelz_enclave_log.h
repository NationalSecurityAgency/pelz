#ifndef _PELZ_ENCLAVE_LOG_H_
/**
 * @file pelz_enclave_log.h
 *
 * @brief  providing the pelz_sgx_log() macro
 */

#define _PELZ_ENCLAVE_LOG_H_

#ifdef __cplusplus
extern "C"
{
#endif

// maximum log message size - can use to size buffer
#define MAX_LOG_MSG_LEN 128

//if 'syslog.h' is not included, define its 'priority' level macros here
#ifndef LOG_EMERG
#define	LOG_EMERG	0
#endif

#ifndef LOG_ALERT
#define	LOG_ALERT	1
#endif

#ifndef LOG_CRIT
#define	LOG_CRIT	2
#endif

#ifndef LOG_ERR
#define	LOG_ERR		3
#endif

#ifndef LOG_WARNING
#define	LOG_WARNING	4
#endif

#ifndef LOG_NOTICE
#define	LOG_NOTICE	5
#endif

#ifndef LOG_INFO
#define	LOG_INFO	6
#endif

#ifndef LOG_DEBUG
#define	LOG_DEBUG	7
#endif

// macro for generic logging call
#define pelz_log(severity, message)\
{\
  const char *src_file = __FILE__;\
  const char *src_func = __func__;\
  const int src_line = __LINE__;\
  int log_level = severity;\
  const char *log_msg = message;\
  log_event_ocall(&src_file, &src_func, &src_line, &log_level, &log_msg);\
}

#ifdef __cplusplus
}
#endif

#endif
