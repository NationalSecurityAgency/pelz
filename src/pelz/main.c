/*
 * Contains the main function used to launch the Pelz Key Service
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <key_table.h>
#include <pelz_service.h>
#include <pelz_socket.h>
#include <pelz_request_handler.h>
#include <CharBuf.h>
#include <pelz_log.h>

void *thread_process(void *arg)
{
  ThreadArgs *args = arg;
  int new_socket;
  CharBuf request;
  CharBuf message;

  new_socket = args->socket_id;

  while (!pelz_key_socket_check(new_socket))
  {
    //Receiving request and Error Checking
    if (pelz_key_socket_recv(new_socket, &request))
    {
      pelz_log(LOG_ERR, "%d::Error Receiving Request", new_socket);
      while (!pelz_key_socket_check(new_socket))
        continue;
      pelz_key_socket_close(new_socket);
      pthread_exit(NULL);
    }

    pelz_log(LOG_DEBUG, "%d::Request & Length: %s, %d", new_socket, request.chars, (int) request.len);

    if (pelz_key_service(request, &message, args->table, new_socket))
      pelz_log(LOG_ERR, "%d::Service Error\nSend error message.", new_socket);

    pelz_log(LOG_DEBUG, "%d::Message & Length: %s, %d", new_socket, message.chars, (int) message.len);
    //Send processed request back to client
    if (pelz_key_socket_send(new_socket, message))
    {
      pelz_log(LOG_ERR, "%d::Socket Send Error", new_socket);
      freeCharBuf(&message);
      while (!pelz_key_socket_check(new_socket))
        continue;
      pelz_key_socket_close(new_socket);
      pthread_exit(NULL);
    }
    freeCharBuf(&message);
  }
  pelz_key_socket_close(new_socket);
  pthread_exit(NULL);
}

//Main function for the Pelz Service application
int main(int argc, char **argv)
{
  const int max_requests = 100;
  int socket_id;
  int socket_listen_id;
  pthread_t tid[max_requests];
  KeyTable key_table;
  ThreadArgs args;

  socket_id = 0;

  set_app_name("pelz");
  set_app_version("0.0.0");
  set_applog_path("/var/log/pelz.log");
  set_applog_severity_threshold(LOG_WARNING);

  //Initializing Key Table with max key entries set to key_max
  if (key_table_init(&key_table))
  {
    pelz_log(LOG_ERR, "Key Table Init Failure");
    return (1);
  }
  args.table = &key_table;

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

    if (socket_id == 0)         //This is to reset the while loop if select() times out
      continue;

    if (socket_id > max_requests)
    {
      pelz_log(LOG_WARNING, "%d::Over max socket requests.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    args.socket_id = socket_id;
    if (pthread_create(&tid[socket_id], NULL, thread_process, &args) != 0)
    {
      pelz_log(LOG_WARNING, "%d::Failed to create thread.", socket_id);
      pelz_key_socket_close(socket_id);
      continue;
    }

    pelz_log(LOG_INFO, "Thread %d, %d", (int) tid[socket_id], socket_id);
  }
  while (socket_listen_id >= 0 && socket_id <= (max_requests + 1));

  //Close and Teardown Socket before ending program
  pelz_key_socket_teardown(&socket_listen_id);
  key_table_destroy(&key_table);
  return (0);
}
