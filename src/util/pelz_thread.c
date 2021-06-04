#include <string.h>
#include <pthread.h>

#include "charbuf.h"
#include "pelz_log.h"
#include "pelz_socket.h"
#include "pelz_json_parser.h"
#include "pelz_io.h"
#include "pelz_request_handler.h"
#include "pelz_thread.h"

void thread_process(void *arg)
{
  ThreadArgs *threadArgs = (ThreadArgs *) arg;
  int new_socket = threadArgs->socket_id;
  pthread_mutex_t lock = threadArgs->lock;

  charbuf request;
  charbuf message;
  RequestResponseStatus status;
  char *err_message;

  while (!pelz_key_socket_check(new_socket))
  {
    //Receiving request and Error Checking
    if (pelz_key_socket_recv(new_socket, &request))
    {
      pelz_log(LOG_ERR, "%d::Error Receiving Request", new_socket);
      while (!pelz_key_socket_check(new_socket))
        continue;
      pelz_key_socket_close(new_socket);
      return;
    }

    pelz_log(LOG_DEBUG, "%d::Request & Length: %.*s, %d", new_socket, (int) request.len, request.chars, (int) request.len);

    RequestType request_type = REQ_UNK;

    charbuf key_id;
    charbuf data_in;
    charbuf data_out;

    charbuf data;
    charbuf output;

    //Parse request for processing
    if (request_decoder(request, &request_type, &key_id, &data_in))
    {
      err_message = "Missing Data";
      error_message_encoder(&message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
      pelz_key_socket_close(new_socket);
      free_charbuf(&request);
      return;
    }

    free_charbuf(&request);

    decodeBase64Data(data_in.chars, data_in.len, &data.chars, &data.len);
    free_charbuf(&data_in);

    pthread_mutex_lock(&lock);
    status = pelz_request_handler(request_type, key_id, data, &output);
    pthread_mutex_unlock(&lock);
    free_charbuf(&data);

    if (status != REQUEST_OK)
    {
      pelz_log(LOG_ERR, "%d::Service Error\nSend error message.", new_socket);
      switch (status)
      {
      case KEK_LOAD_ERROR:
        err_message = "Key not added";
        break;
      case KEY_OR_DATA_ERROR:
        err_message = "Key or Data Error";
        break;
      case ENCRYPT_ERROR:
        err_message = "Encrypt Error";
        break;
      case DECRYPT_ERROR:
        err_message = "Decrypt Error";
        break;
      case REQUEST_TYPE_ERROR:
        err_message = "Request Type Error";
        break;
      default:
        err_message = "Unrecognized response";
      }
      error_message_encoder(&message, err_message);
    }
    else
    {
      encodeBase64Data(output.chars, output.len, &data_out.chars, &data_out.len);
      if (strlen((char *) data_out.chars) != data_out.len)
      {
        data_out.chars[data_out.len] = 0;
      }
      message_encoder(request_type, key_id, data_out, &message);
      pelz_log(LOG_DEBUG, "%d::Message Encode Complete", new_socket);
      pelz_log(LOG_DEBUG, "%d::Message: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
    }
    free_charbuf(&key_id);
    free_charbuf(&data_out);
    free_charbuf(&output);

    pelz_log(LOG_DEBUG, "%d::Message & Length: %.*s, %d", new_socket, (int) message.len, message.chars, (int) message.len);
    //Send processed request back to client
    if (pelz_key_socket_send(new_socket, message))
    {
      pelz_log(LOG_ERR, "%d::Socket Send Error", new_socket);
      free_charbuf(&message);
      while (!pelz_key_socket_check(new_socket))
        continue;
      pelz_key_socket_close(new_socket);
      return;
    }
    free_charbuf(&message);
  }
  pelz_key_socket_close(new_socket);
  return;
}
