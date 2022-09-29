#ifndef INCLUDE_FIFO_THREAD_H_
#define INCLUDE_FIFO_THREAD_H_

#include <stdbool.h>
#include <pthread.h>
#include <secure_socket_thread.h>

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

#endif
