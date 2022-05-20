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
  int socket_listen_id;
  int secure_socket_listen_id;
  ThreadArgs threadArgs;

  pthread_mutex_t lock;

  pthread_mutex_init(&lock, NULL);

  //Initializing Socket for Pelz Key Service
  if (pelz_key_socket_init(max_requests, port_attested, &secure_socket_listen_id))
  {
    pelz_log(LOG_ERR, "Socket Initialization Error");
    return (1);
  }
  pelz_log(LOG_DEBUG, "Socket on port %d created with listen_id of %d", port_attested, secure_socket_listen_id);

  if (!secure)
  {
    if (pelz_key_socket_init(max_requests, port_open, &socket_listen_id))
    {
      pelz_log(LOG_ERR, "Socket Initialization Error");
      return (1);
    }
    pelz_log(LOG_DEBUG, "Socket on port %d created with listen_id of %d", port_open, socket_listen_id);
  }

  threadArgs.lock = lock;
  pthread_t fifo_thread;

  if (pthread_create(&fifo_thread, NULL, fifo_thread_process, &threadArgs))
  {
    pelz_log(LOG_ERR, "Unable to start thread to monitor named pipe");
    return 1;
  }

  threadArgs.lock = lock;
  threadArgs.socket_id = socket_listen_id;
  threadArgs.max_requests = max_requests;
  pthread_t unsecure_socket_thread;

  if (pthread_create(&unsecure_socket_thread, NULL, unsecure_thread_wrapper, &threadArgs))
  {
    pelz_log(LOG_ERR, "Unable to start thread to monitor unsecure socket");
    return 1;
  }
  pelz_log(LOG_INFO, "Unsecure Listen Socket Thread %d, %d", (int) unsecure_socket_thread, socket_listen_id);

  threadArgs.lock = lock;
  threadArgs.socket_id = secure_socket_listen_id;
  threadArgs.max_requests = max_requests;
  pthread_t secure_socket_thread;

  if (pthread_create(&secure_socket_thread, NULL, secure_thread_wrapper, &threadArgs))
  {
    pelz_log(LOG_ERR, "Unable to start thread to monitor secure socket");
    return 1;
  }
  pelz_log(LOG_INFO, "Secure Listen Socket Thread %d, %d", (int) secure_socket_thread, secure_socket_listen_id);

  printf("Threads created and waiting for exit command.\n");
  if (global_pipe_reader_active)
    printf("global_pipe_reader_active = true\n");

  do
  {
    if (global_pipe_reader_active)
    {
      continue;
    }
    printf("global_pipe_reader_active = false\n");
    break;
  }while (global_pipe_reader_active);

  printf("Exit from Pelz Program\n");
  pelz_log(LOG_INFO, "Exit Pelz Program");

  //Close and Teardown Socket before ending program
  pelz_key_socket_teardown(&socket_listen_id);
  pelz_key_socket_teardown(&secure_socket_listen_id);
  pthread_mutex_destroy(&lock);
  return 0;
}
