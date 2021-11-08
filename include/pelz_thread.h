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
  pthread_mutex_t *listener_mutex;
  int return_value;
} ListenerThreadArgs;

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

/**
 * <pre>
 * Listener function that receives responses from the pelz-service.
 * </pre>
 *
 * @param[in,out] args a pointer to a ListenerThreadArgs structure
 *                     containing a mutex to indicate (by unlocking) 
 *                     that the listener is ready, and an int to hold 
 *                     the result of the function call.
 *
 * @return none
 */
void *pelz_listener(void *args);

#endif
