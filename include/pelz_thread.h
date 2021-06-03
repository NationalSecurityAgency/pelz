#ifndef INCLUDE_PELZ_THREAD_H_
#define INCLUDE_PELZ_THREAD_H_

#include <pthread.h>

typedef struct
{
  int socket_id;
  pthread_mutex_t lock;
} ThreadArgs;

/**
 * <pre>
 * Function executed on each thread by pelz_service
 * <pre>
 * 
 * @param[in] arg a pointer to a structure containing the 
 *                socket id for that thread and the key table
 *                mutex.
 *
 * @return none
 */
void thread_process(void *arg);

#endif
