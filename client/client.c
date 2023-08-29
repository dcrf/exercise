/**
 * Copyright 2023 dfranca
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "client.h"
#include "common.h"
#include "sha256.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>

#define CLIENT_CONNECT_RETRIES          (3)
#define CLIENT_COMMUNICATION_TIMEOUT_MS (90000)

// Shared 8Kbytes buffer used to:
// a) Calculate local file sha256
// b) Calculate Rabin fingerprints
// c) Exchange message with server side
static uint8_t common_buffer[8u * 1024u] = { 0 };

/**
 * @brief Auxiliary  file transfer steps to drive transfer FSM.
 * 
 */
typedef enum
{
    CLIENT_WAIT_READY_CMD_FROM_SERVER = 0,
    CLIENT_REQUEST_FULL_FILE_TRANSFER,
    CLIENT_FINISHED_FILE_TRANSFER,
    CLIENT_NO_OPERATION
} client_file_op_t;

typedef struct 
{
    const char *p_server_ipv4;
    const char *p_server_port;
    const char *p_file_name;
    uint8_t *p_buffer;     
    volatile bool *p_run;
    bool file_exists;
    uint8_t file_sha256_hash[SHA256_DIGEST_SIZE];
    client_file_op_t current_operation;
    client_file_op_t next_operation;
    int socket;
} client_app_ctx;


// Auxiliary functions:
static int32_t connect_with_remote_server(void);

static client_app_ctx client = { 0 };


// This function will return after at least one of these conditions are true:
// a) A CTRL + C was intercepted to exit the application in client mode
// b) The requested file does not exist on the server.
// c) The local and requested files are the same.
// d) The requested file was transferred from server to client.        
// e) No response from the server after 90s.

int32_t run_application_in_client_mode(const char *p_server_ipv4, 
                                       const char *p_server_port,
                                       const char *p_file_name,
                                       volatile bool *p_run)
{
    int32_t result = -1;

    client.p_buffer = common_buffer;
    client.p_server_ipv4 = p_server_ipv4;
    client.p_server_port = p_server_port;
    client.p_file_name = p_file_name;
    client.p_run = p_run;

    client.current_operation = CLIENT_WAIT_READY_CMD_FROM_SERVER;
    client.next_operation = CLIENT_NO_OPERATION;
    
    // Check if the requested file exists on client side:
    client.file_exists = file_exists(p_file_name);

    if (client.file_exists)
    {
        file_calculate_sha256(p_file_name, client.p_buffer, sizeof(common_buffer), client.file_sha256_hash);
    }

    if (!connect_with_remote_server())
    {
        return -1;
    }

    // Client has established a valid TCP connection with remote server
    // Client will exit the next loop when one of these conditions happens:
    //
    // a) The requested file does not exist on the server side.
    // b) The requested file was properly updated (full file transfer or diff transfer based on Rabin fingerprints)
    // c) The server does not respond the client for a period of 90s.

    struct pollfd pfds[1];
    pfds[0].fd = client.socket;
    pfds[0].events = POLLIN | POLLERR;

    for (;;)
    {
        poll(pfds, 1, CLIENT_COMMUNICATION_TIMEOUT_MS)



    }    

    return 0;
}

static int32_t connect_with_remote_server(void)
{
    // Create client TCP socket:
    // TCP has substantial more protocol overhead than UDP but as we are dealing with file transfer I will choose using TCP.
    // One second option would be using UDP sockets and implement a basic packet retransmisson/acknowledgement on the applicaton layer.
    // As I have very limited free time I will play safe to have something to show regarding this exercise and go with the TCP.
    // But I know that the exercise explains that our network has a high latency. UDP sockets would be a potential better solution for a real case
    // product and implementing a rudimentary/basic application retransmission logic. 

    errno = 0;
    client.socket = socket(AF_INET, SOCK_STREAM, 0);

    if (-1 == client.socket)
    {
        printf("\r\nFailed to create a client TCP socket - error: %d", errno);
        return -1;
    }

    // Try to establish a connection with the remote server:
    // After a successfull connection the client side will wait for a "ready" message from the server.
    // Why not start communicating immediatelly with the server ? Because on the server side I will implement a pool of thread with a
    // maximum number of threads. This is to avoid the server spawming too many threads that can degrade the system.
    // If the server has no available thread from its pool: it will still accept the client connection but wait till one worker thread is available.
    // The client side will wait up to 90s for a response from the server. If no response received the client will exits.

    struct addrinfo info = { 0 };

    info.ai_family = AF_INET;
    info.ai_socktype = SOCK_STREAM;
    info.ai_protocol = IPPROTO_TCP;

    // Resolve remote server address:
    struct addrinfo *p_result = NULL;
    int32_t result = getaddrinfo(client.p_server_ipv4, client.p_server_port, &info, &p_result);

    if (0 != result)
    {
        const char *p_error = gai_strerror(result);
        printf("\r\nFailed to resolve remote server address %s:%s - error: %s",  client.p_server_ipv4, client.p_server_port, p_error);
        return -1;
    }

    // Try up to 3 times to establish a connection with remote server:
    
    for (int32_t i = 0; i < CLIENT_CONNECT_RETRIES; ++i)
    {
        result = connect(client.socket, p_result->ai_addr, p_result->ai_addrlen);

        if (0 == result)
        {
            printf("\r\nSuccessfully connected to remote server %s:%s\r\n", client.p_server_ipv4, client.p_server_port);
            break;
        }

        printf("\r\nFailed to connect to remote server address %s:%s\r\n", client.p_server, client.p_port);
        printf("Retry in 1[s]\r\n");
        sleep(1u);
    }    

    freeaddrinfo(p_result);

    return result;
} 