#ifndef INCLUDE_PELZ_THREAD_H_
#define INCLUDE_PELZ_THREAD_H_

#include <pthread.h>

typedef struct
{
  int socket_id;
  pthread_mutex_t lock;
} ThreadArgs;

void *thread_process(void *arg);

#endif
