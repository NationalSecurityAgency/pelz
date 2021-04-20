#include <string.h>
#include "CharBuf.h"
#include "pelz_log.h"
#include "pelz_socket.h"
#include "pelz_json_parser.h"
#include "pelz_io.h"

void thread_process(void *arg)
{
  int *socket_id = (int *) arg;
  int new_socket = *socket_id;
  CharBuf request;
  CharBuf message;

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

    pelz_log(LOG_DEBUG, "%d::Request & Length: %s, %d", new_socket, request.chars, (int) request.len);

    RequestType request_type = 0;
    CharBuf key_id;
    CharBuf data_in;
    CharBuf data_out;

    CharBuf data;
    CharBuf output;
    char *err_message;

    //Parse request for processing
    if (request_decoder(request, &request_type, &key_id, &data_in))
    {
      err_message = "Missing Data";
      error_message_encoder(&message, err_message);
      pelz_log(LOG_DEBUG, "%d::Error: %s, %d", socket_id, message.chars, (int) message.len);
      pelz_key_socket_close(new_socket);
      freeCharBuf(&request);
      return;
    }

    freeCharBuf(&request);

    decodeBase64Data(data_in.chars, data_in.len, &data.chars, &data.len);
    freeCharBuf(&data_in);

    if (pelz_request_handler(request_type, key_id, data, output, &message, new_socket))
    {
      pelz_log(LOG_ERR, "%d::Service Error\nSend error message.", new_socket);
    }

    freeCharBuf(&data);
    encodeBase64Data(output.chars, output.len, &data_out.chars, &data_out.len);
    if (strlen((char *) data_out.chars) != data_out.len)
    {
      data_out.chars[data_out.len] = 0;
    }

    message_encoder(request_type, key_id, data_out, &message);
    pelz_log(LOG_DEBUG, "%d::Message Encode Complete", socket_id);
    pelz_log(LOG_DEBUG, "%d::Message: %s, %d", socket_id, message.chars, (int) message.len);
    freeCharBuf(&key_id);
    freeCharBuf(&data_out);
    freeCharBuf(&output);

    pelz_log(LOG_DEBUG, "%d::Message & Length: %s, %d", new_socket, message.chars, (int) message.len);
    //Send processed request back to client
    if (pelz_key_socket_send(new_socket, message))
    {
      pelz_log(LOG_ERR, "%d::Socket Send Error", new_socket);
      freeCharBuf(&message);
      while (!pelz_key_socket_check(new_socket))
        continue;
      pelz_key_socket_close(new_socket);
      return;
    }
    freeCharBuf(&message);
  }
  pelz_key_socket_close(new_socket);
  return;
}
