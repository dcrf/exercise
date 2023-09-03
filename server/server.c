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

#include "common.h"
#include "server.h"
#include "thpool.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef struct
{
    volatile bool *p_run;
    const char *p_server_port;
    threadpool pool;
    size_t max_number_of_worker_threads;
    size_t max_number_of_connections;
    int listening_socket;
} server_app_ctx;

// Private auxiliary functions:
static void cleanup(void);
static int create_listening_socket(void);
static int32_t server_process_clients(void);
static void file_transfer_work_function(int client_socket);

static server_app_ctx server = { 0 };

int32_t run_application_in_server_mode(const char *p_server_port, volatile bool *p_run)
{
    int32_t result = -1;

    // Initialize server context control variable:
    server.listening_socket = -1;
    server.p_run = p_run;
    server.p_server_port = p_server_port;
    server.max_number_of_worker_threads = SERVER_NUMBER_OF_WORKER_THREADS;
    server.max_number_of_connections = SERVER_MAX_NUMBER_OF_WAITING_JOBS;

    server.pool = thpool_init(server.max_number_of_worker_threads);

    server.listening_socket = create_listening_socket();

    if (-1 != server.listening_socket)
    {
        // Server will return only when a shutdown was requested by customer
        result = server_process_clients();
    }

    cleanup();

    return result;
}

static int32_t server_process_clients(void)
{
    int32_t result = -1;

    struct pollfd fds[1];
    memset(fds, 0x00, sizeof(fds));

    fds[0].fd = server.listening_socket;
    fds[0].events = POLLIN | POLLERR | POLLHUP;

    // To give opportunity to "server.p_run" being evaluated
    const int socket_timeout_ms = 5000;

    // Enters in a loop to receive new client connections and dispatch work for the thread pool:
    while (*server.p_run)
    {
        result = poll(fds, 1, socket_timeout_ms);

        const short revents = fds[0].revents;

        if (0 == result)
        {
            // Server listening socket has timed-out:
            if (*server.p_run == false)
            {
                // Controlled shutdown was requested
                result = 0;
            }
        }
        else
        {
            if (revents & POLLIN)
            {
                // Listening socket has at least one pending client connection queued (can have more):
                // We need to be careful with the maximum allowed numbers of clients on the jobs queue:

                int client_socket = -1;
                bool continue_accepting_clients = true;

                do
                {
                    struct sockaddr_storage client_info;
                    socklen_t size = sizeof(client_info);
                    memset(&client_info, 0x00, sizeof(client_info));

                    errno = 0;
                    client_socket = accept(server.listening_socket, (struct sockaddr *)&client_info, &size);

                    if (-1 == client_socket)
                    {
                        if ((EWOULDBLOCK == errno) || (EAGAIN == errno))
                        {
                            // There is no more pending connections waiting on the queue
                            continue_accepting_clients = false;
                        }
                    }
                    else
                    {
                        // Do we have enough jobs available to process the new client socket ?
                        if (thpool_num_jobs_on_queue(server.pool) < SERVER_MAX_NUMBER_OF_WAITING_JOBS)
                        {
                            thpool_add_work(server.pool, file_transfer_work_function, client_socket);
                        }
                        else
                        {
                            // Unfortunately we have no more available jobs on the queue to store this new client:
                            shutdown(client_socket, SHUT_RDWR);
                            close(client_socket);
                        }
                    }

                } while (continue_accepting_clients);
            }
            else // POLLERR | POLLHP
            {
                result = -1;
                break;
            }
        }
    }

    return result;
}

static void file_transfer_work_function(int client_socket)
{
    uint8_t client_buffer[RABIN_MAX_BLOCK_SIZE + 64u];

    // This function will take care of the client file transfer until it finishes or a shutdown is requested
    while (*server.p_run)
    {

    }

    (void)(client_socket);
    (void)(client_buffer);
}

static int create_listening_socket(void)
{
    struct sockaddr_in in_server;
    memset(&in_server, 0x00, sizeof(in_server));

    in_server.sin_family = AF_INET;
    in_server.sin_addr.s_addr = INADDR_ANY;
    in_server.sin_port = htons(atoi(server.p_server_port));

    // Create the listening socket:
    int listening_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (-1 == listening_socket)
    {
        return -1;
    }

    // Allow our server to bind again to this address without waiting for TIME_WAIT
    socklen_t enable = 1;
    errno = 0;
    if (-1 == setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(socklen_t)))
    {
        printf("\r\nFailed 'setsockopt' [%d]\r\n", errno);
        return -1;
    }

    // Change listening socket for non-blocking (we are going to use 'poll' interface):
    int flags = fcntl(listening_socket, F_GETFL);
    fcntl(listening_socket, F_SETFL, flags | O_NONBLOCK);
    
    // Bind socket to specified port:
    errno = 0;
    if (-1 == bind(listening_socket, (struct sockaddr *)&in_server, sizeof(in_server)))
    {
        printf("\r\nFailed to bind the listening socket [%d]\r\n", errno);
        return -1;
    }

    // Change socket for listening mode:
    errno = 0;
    if (-1 == listen(listening_socket, SERVER_NUMBER_OF_WORKER_THREADS))
    {
        printf("\r\nFailed to start listening on socket[%d]\r\n", errno);
        return -1;
    }

    return listening_socket;
}

static void cleanup(void)
{
    // Stop accepting more socket connections:
    if (-1 == server.listening_socket)
    {
        shutdown(server.listening_socket, SHUT_RDWR);
        close(server.listening_socket);
        server.listening_socket = -1;
    }

    // Wait for current working threads to finish and release the threadpool resources:
    if (server.pool)
    {
        thpool_wait(server.pool);
        thpool_destroy(server.pool);
        server.pool = NULL;
    }
}