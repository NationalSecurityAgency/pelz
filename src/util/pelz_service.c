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
#include "fifo_thread.h"
#include "unsecure_socket_thread.h"
#include "secure_socket_thread.h"

bool global_pipe_reader_active = true;
bool global_secure_socket_active = false;
bool global_unsecure_socket_active = false;

static void *unsecure_thread_wrapper(void *arg)
{
  unsecure_socket_thread(arg);
  pthread_exit(NULL);
}

static void *secure_thread_wrapper(void *arg)
{
  secure_socket_thread(arg);
  pthread_exit(NULL);
}

int pelz_service(int max_requests, int port_open, int port_attested, bool secure)
{
  ThreadArgs threadArgs;

  pthread_mutex_t lock;

  pthread_mutex_init(&lock, NULL);

  threadArgs.lock = lock;
  pthread_t fifo_thread;

  if (pthread_create(&fifo_thread, NULL, fifo_thread_process, &threadArgs))
  {
    pelz_log(LOG_ERR, "Unable to start thread to monitor named pipe");
    return 1;
  }

  if (!secure)
  {
    threadArgs.lock = lock;
    threadArgs.port = port_open;
    threadArgs.max_requests = max_requests;
    pthread_t unsecure_socket_thread;

    if (pthread_create(&unsecure_socket_thread, NULL, unsecure_thread_wrapper, &threadArgs))
    {
      pelz_log(LOG_ERR, "Unable to start thread to monitor unsecure socket");
      return 1;
    }
    pelz_log(LOG_INFO, "Unsecure Listen Socket Thread %d, %d", (int) unsecure_socket_thread, port_open);
  }

  threadArgs.lock = lock;
  threadArgs.port = port_attested;
  threadArgs.max_requests = max_requests;
  pthread_t secure_socket_thread;

  if (pthread_create(&secure_socket_thread, NULL, secure_thread_wrapper, &threadArgs))
  {
    pelz_log(LOG_ERR, "Unable to start thread to monitor secure socket");
    return 1;
  }
  pelz_log(LOG_INFO, "Secure Listen Socket Thread %d, %d", (int) secure_socket_thread, port_attested);

  do
  {
    if (!global_unsecure_socket_active & global_pipe_reader_active)
    {
      pelz_log(LOG_DEBUG, "Unsecure socket closed");
    }
    if (!global_secure_socket_active & global_pipe_reader_active)
    {
      pelz_log(LOG_DEBUG, "Secure socket closed");
    }
    continue;  
  } while (global_pipe_reader_active || global_unsecure_socket_active || global_secure_socket_active);

  pelz_log(LOG_INFO, "Exit Pelz Program");

  //Close and Teardown Socket before ending program
  pthread_mutex_destroy(&lock);
  return 0;
}
