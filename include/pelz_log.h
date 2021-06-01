/*
 * pelz_log.h
 */

#ifndef INCLUDE_PELZ_LOG_H_
#define INCLUDE_PELZ_LOG_H_

#ifndef PELZ_SGX
#include <kmyth/kmyth_log.h>

/**
 * @brief macro used to specify common initial three kmyth_log() parameters
 */
#define pelz_log(...) log_event(__FILE__, __func__, __LINE__, __VA_ARGS__)
#else
#define pelz_log(...)
#endif
#endif /* INCLUDE_PELZ_LOG_H_ */
