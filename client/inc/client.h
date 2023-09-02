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


/**
 * @brief Initialize the application in client mode to request a file transfer from the server
 *
 * @param p_server_ipv4 Server IPv4 to connect with
 * @param p_server_port Server socket port
 * @param p_file_name   File name to update (from server to client)
 * @param p_run         Flag used to control the application shutdown
 * @return int32_t      Return value of the file transfer operation
 */
int32_t run_application_in_client_mode(const char *p_server_ipv4,
                                       const char *p_server_port,
                                       const char *p_file_name,
                                       volatile bool *p_run);