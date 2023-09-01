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

#ifndef COMMON_HEADER_
#define COMMON_HEADER_

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define PRINT_DBG_MSGS  (1)
#define SUCCESS         (0)

#define DO_NOTHING()    do{}while(0)

/**
 * @brief Auxiliary CLIENT file transfer steps
 * 
 */
typedef enum
{
    CLIENT_RECEIVED_CMD_FULL,
    CLIENT_RECEIVED_CMD_PARTIAL,
    CLIENT_RECEIVED_CMD_ERROR,
    CLIENT_RECEIVED_FULL_FILE,
    CLIENT_NO_OPERATION
} client_file_op_t;

/**
 * @brief Enumeration of application running modes
 * 
 */
typedef enum 
{
    APP_CLIENT_MODE = 0,
    APP_SERVER_MODE = 1,
    APP_UNKNOWN_MODE = 2
} app_mode_t;

/**
 * @brief Checks if a string contains a valid IPv4 address
 * 
 * @param p_ipv4 Pointer to a buffer with the IPv4 string to be checked
 * @return true 
 * @return false 
 */
bool is_valid_ipv4(const char *p_ipv4);

/**
 * @brief Checks if a file exists
 * 
 * @param p_file_name Pointer to a buffer with the file name to be checked
 * @return true 
 * @return false 
 */
bool file_exists(const char *p_file_name);

/**
 * @brief Calculates the SHA-256 hash of a file contents
 * 
 * @param p_file_name File name which SHA256 will be calculated
 * @param p_data_buffer Temporary buffer to read file data
 * @param size Size of temporary data buffer in bytes
 * @param p_sha256_digest Pointer to a buffer (32 bytes) to receive the SHA-256 digest
 * @return true 
 * @return false 
 */
bool file_calculate_sha256(const char *p_file_name, uint8_t *p_data_buffer, size_t size, uint8_t *p_sha256_digest);

/**
 * @brief Auxiliary debug function to convert a hexadecimal buffer into a string (based on code from stack overflow)
 * 
 * @param p_input_buffer Input bytes to be converted to string
 * @param p_output_buffer Output buffer with input buffer converted to ASCII
 * @param length Size of the input buffer
 * @return Pointer to output buffer (null terminated)
 */
const char * convert_to_hex(const uint8_t *p_input_buffer, int32_t length, char * p_output_buffer);

#endif //COMMON_HEADER_
