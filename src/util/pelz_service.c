/*
 * pelz_key_service.c
 */
#include <pelz_service.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pelz_socket.h"
#include "pelz_log.h"
#include "pelz_io.h"
#include "pelz_thread.h"
#include "key_table.h"

#include "sgx_urts.h"
#include "pelz_enclave.h"
#include "pelz_enclave_u.h"

#define PELZFIFO "/tmp/pelzfifo"
#define BUFSIZE 1024

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

  int fd;
  int ret;
  int ex = 0;
  int mode = 0777;              //the file premissions to set rw for all users
  char buf[BUFSIZE];            //the buffer size is defined by BUFSIZE
  char opt;
  charbuf key_id;

  if (mkfifo(PELZFIFO, mode) == 0)
    pelz_log(LOG_INFO, "Pipe created successfully");
  else
    pelz_log(LOG_INFO, "Error: %s", strerror(errno));

  socket_id = 0;

  pthread_mutex_t lock;

  pthread_mutex_init(&lock, NULL);

  //Initializing Socket for Pelz Key Service
  if (pelz_key_socket_init(max_requests, &socket_listen_id))
  {
    pelz_log(LOG_ERR, "Socket Initialization Error");
    return (1);
  }

  do
  {
    if (pelz_key_socket_accept(socket_listen_id, &socket_id))
    {
      pelz_log(LOG_ERR, "Socket Client Connection Error");
      continue;
    }

    fd = open(PELZFIFO, O_RDONLY);
    ret = read(fd, buf, sizeof(buf));
    close(fd);
    if (ret > 0)
    {
      if (memcmp(buf, "pelz -", 6) == 0)
      {
        opt = buf[6];
    	pelz_log(LOG_INFO, "Pipe message: %d, %c, %s", strlen(buf), opt,  buf);
        switch (opt)
        {
        case 'w':
      	  key_table_destroy(eid, &ret);
          if (ret)
          {
            pelz_log(LOG_ERR, "Key Table Destroy Failure");
            return (1);
          }
          pelz_log(LOG_INFO, "Key Table Destroyed");
          key_table_init(eid, &ret);
          if (ret)
          {
            pelz_log(LOG_ERR, "Key Table Init Failure");
            return (1);
          }
	  pelz_log(LOG_INFO, "Key Table Re-Initialized");
	  break;
        case 'd':
          key_id = new_charbuf(strlen(buf) - 7);
          memcpy(key_id.chars, &buf[8], key_id.len);
	  key_table_delete(eid, &ret, key_id);
          if(ret)
            pelz_log(LOG_ERR, "Delete Key ID from Key Table Failure: %.*s", (int) key_id.len, key_id.chars);
	  else
            pelz_log(LOG_INFO, "Delete Key ID form Key Table: %.*s", (int) key_id.len, key_id.chars);
	  break;
        case 'e':
          ex = 1;
          if (unlink(PELZFIFO) == 0)
      	    pelz_log(LOG_INFO, "Pipe deleted successfully");
          else
            pelz_log(LOG_INFO, "Failed to delete the pipe: %s", strerror(errno));
       	  break;
        default:
	  pelz_log(LOG_ERR, "Pipe command invalid");
	}
      }
      else
        pelz_log(LOG_ERR, "Pipe command invalid");   
    }
    if (ex)
      break;

    if (socket_id == 0)         //This is to reset the while loop if select() times out
      continue;

    if (socket_id > max_requests)
    {
      pelz_log(LOG_WARNING, "%d::Over max socket requests.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    ThreadArgs threadArgs;

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
  while (socket_listen_id >= 0 && socket_id <= (max_requests + 1));

  pelz_log(LOG_INFO, "Exit Pelz Program");

  //Close and Teardown Socket before ending program
  pelz_key_socket_teardown(&socket_listen_id);
  pthread_mutex_destroy(&lock);
  return 0;
}
