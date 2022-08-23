/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "fifo_def.h"

// The Initiator demo originally used a new socket connection for each message,
// but Pelz expects a single persistent connection for the entire session.
static int server_sock_fd = -1;


// Create a socket and connect to the server_name:server_port
// This function was adapted from create_socket() in
// linux-sgx/SampleCode/SampleAttestedTLS/non_enc_client/client.cpp
int connect_to_server(char* server_name, char* server_port)
{
    int sockfd = -1;
    struct addrinfo hints, *dest_info, *curr_di;
    int res;

    hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((res = getaddrinfo(server_name, server_port, &hints, &dest_info)) != 0)
    {
        printf(
            "Error: Cannot resolve hostname %s. %s\n",
            server_name,
            gai_strerror(res));
        goto done;
    }

    curr_di = dest_info;
    while (curr_di)
    {
        if (curr_di->ai_family == AF_INET)
        {
            break;
        }

        curr_di = curr_di->ai_next;
    }

    if (!curr_di)
    {
        printf(
            "Error: Cannot get address for hostname %s.\n",
            server_name);
        goto done;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    if (connect(
            sockfd,
            (struct sockaddr*)curr_di->ai_addr,
            sizeof(struct sockaddr)) == -1)
    {
        printf(
            "failed to connect to %s:%s (errno=%d)\n",
            server_name,
            server_port,
            errno);
        close(sockfd);
        sockfd = -1;
        goto done;
    }
    printf("connected to %s:%s\n", server_name, server_port);

done:
    if (dest_info)
        freeaddrinfo(dest_info);

    server_sock_fd = sockfd;

    return sockfd;
}


/* Function Description: this is for client to send request message and receive response message
 * Parameter Description:
 * [input] fiforequest: this is pointer to request message
 * [input] fiforequest_size: this is request message size
 * [output] fiforesponse: this is pointer for response message, the buffer is allocated inside this function
 * [output] fiforesponse_size: this is response message size
 * */
int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size)
{
    int ret = 0;
    long byte_num;
    char recv_msg[BUFFER_SIZE + 1] = {0};
    FIFO_MSG * response = NULL;

    // The original version of this function created a UNIX socket connection here.

    byte_num = recv(server_sock_fd, reinterpret_cast<char *>(recv_msg), BUFFER_SIZE, 0);
    if (byte_num > 0)
    {
        if (byte_num > BUFFER_SIZE)
        {
            byte_num = BUFFER_SIZE;
        }

        recv_msg[byte_num] = '\0';

        response = (FIFO_MSG *)malloc((size_t)byte_num);
        if (!response)
        {
            printf("memory allocation failure.\n");
            ret = -1;
            goto CLEAN;
        }
        memset(response, 0, (size_t)byte_num);

        memcpy(response, recv_msg, (size_t)byte_num);

        *fiforesponse = response;
        *fiforesponse_size = (size_t)byte_num;

        ret = 0;
    }
    else if(byte_num < 0)
    {
        printf("server error, error message is %s!\n", strerror(errno));
        ret = -1;
    }
    else
    {
        printf("server exit!\n");
        ret = -1;
    }


CLEAN:
    close(server_sock_fd);

    return ret;
}

