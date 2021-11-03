#ifndef INCLUDE_PELZ_THREAD_H_
#define INCLUDE_PELZ_THREAD_H_

#include <pthread.h>

extern bool global_pipe_reader_active;

typedef struct
{
  int socket_id;
  pthread_mutex_t lock;
} ThreadArgs;

typedef struct
{
  char *pipe;
  pthread_mutex_t *reader_lock;
  int return_value;
} pelz_listener_thread_args;

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

/**
 * <pre>
 * Function executed to read the fifo
 * <pre>
 *
 * @param[in] arg a pointer to a structure containing the
 *                socket id for that thread and the key table
 *                mutex. Args currently unused
 *
 * @return none
 */
void *fifo_thread_process(void *arg);

void *pelz_listener(void *pipe);

#endif
