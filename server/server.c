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

#include "server.h"
#include "thpool.h"

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

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


    cleanup();

    return result;
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
    thpool_destroy(server.pool);
    server.pool = NULL;
}