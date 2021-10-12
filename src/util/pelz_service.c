/*
 * pelz_key_service.c
 */
#include <pelz_service.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>

#include "pelz_socket.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "pelz_thread.h"

bool global_pipe_reader_active = true;

static void *thread_process_wrapper(void *arg)
{
  thread_process(arg);
  pthread_exit(NULL);
}

int pelz_service(int max_requests)
{
  int socket_id;
  int socket_listen_id;
  pthread_t tid[max_requests];
  ThreadArgs threadArgs;

  socket_id = 0;

  pthread_mutex_t lock;

  pthread_mutex_init(&lock, NULL);

  //Initializing Socket for Pelz Key Service
  if (pelz_key_socket_init(max_requests, &socket_listen_id))
  {
    pelz_log(LOG_ERR, "Socket Initialization Error");
    return (1);
  }

  threadArgs.lock = lock;
  pthread_t fifo_thread;

  if (pthread_create(&fifo_thread, NULL, fifo_thread_process, &threadArgs))
  {
    pelz_log(LOG_ERR, "Unable to start thread to monitor named pipe");
    return 1;
  }

  do
  {
    if (pelz_key_socket_accept(socket_listen_id, &socket_id))
    {
      pelz_log(LOG_ERR, "Socket Client Connection Error");
      continue;
    }

    if (socket_id == 0)         //This is to reset the while loop if select() times out
    {
      continue;
    }

    if (socket_id > max_requests)
    {
      pelz_log(LOG_WARNING, "%d::Over max socket requests.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    threadArgs.lock = lock;
    threadArgs.socket_id = socket_id;
    if (pthread_create(&tid[socket_id], NULL, thread_process_wrapper, &threadArgs) != 0)
    {
      pelz_log(LOG_WARNING, "%d::Failed to create thread.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    pelz_log(LOG_INFO, "Thread %d, %d", (int) tid[socket_id], socket_id);
  }
  while (socket_listen_id >= 0 && socket_id <= (max_requests + 1) && global_pipe_reader_active);

  pelz_log(LOG_INFO, "Exit Pelz Program");

  //Close and Teardown Socket before ending program
  pelz_key_socket_teardown(&socket_listen_id);
  pthread_mutex_destroy(&lock);
  return 0;
}
