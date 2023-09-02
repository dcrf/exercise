// Copyright 2023 dfranca
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


// Some constants to limit resources usage on the server application:
// We belive the server will be mostly IO intensive than CPU intensive
// Having an IO intensive behaviour we expect that will be common for a worker thread to wait till the low-level IO happens on the Kernel
// Thats the reason we are creating a relatively large ammount of threads and giving a relation of 3 jobs (file transfer) per worker thread
#define SERVER_NUMBER_OF_WORKER_THREADS     (16u)
#define SERVER_MAX_NUMBER_OF_WAITING_JOBS   (3u * SERVER_NUMBER_OF_WORKER_THREADS)

/**
 * @brief Run the application in server mode
 *        Server will start listening for TCP connection at port 'p_server_port'
 *
 * @param p_server_port Server socket port to start listening for conections
 * @param p_run         Controls the application shutdown
 * @return int32_t      0 (graceful shtudown), -1 (error during operation/shutdown)
 */
int32_t run_application_in_server_mode(const char *p_server_port, volatile bool *p_run);