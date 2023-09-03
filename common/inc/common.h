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
#include <sys/socket.h>

/**
 * @brief Auxiliary steps to drive client`s FSM
 *
 */
typedef enum
{
    START_RECEIVING_CMD = 0,
    RECEIVED_CMD_ERROR,
    RECEIVED_CMD_PARTIAL,
    RECEIVED_CMD_FULL,
    RECEIVED_FULL_FILE,
    SOCKET_DISCONNECTED_BY_PEER
} operation_t;

// Rabin Fingerprint constants:
#define RABIN_WINDOW_SIZE       (32u)
#define RABIN_MIN_BLOCK_SIZE    (2u * 1024u)
#define RABIN_AVG_BLOCK_SIZE    (4u * 1024u)
#define RABIN_MAX_BLOCK_SIZE    (8u * 1024u)

// Sanity check the maximum size of the file name:
#define FILE_NAME_MAX_STRING_SIZE   (32)

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
 * @brief Calculates the SHA-256 hash of a whole file contents
 *
 * @param p_file_name File name which SHA256 will be calculated
 * @param p_data_buffer Temporary buffer to read file data
 * @param size Size of temporary data buffer in bytes
 * @param p_sha256_digest Pointer to a buffer (32 bytes) to receive the SHA-256 digest
 */
void file_calculate_sha256(const char *p_file_name, uint8_t *p_data_buffer, size_t size, uint8_t *p_sha256_digest);

/**
 * @brief Calculates the SHA-256 of a slice of a file
 *
 * @param file Stream file descriptor of file to read its slices
 * @param offset Offset within the file to start reading data
 * @param size Number of bytes to read starting at 'offset'
 * @param p_sha256_digest SHA-256 hash of the slice
 */
void file_calculate_sha256_slice(FILE *file, long offset, uint16_t size, uint8_t *p_sha256_digest);

/**
 * @brief Auxiliary debug function to convert a hexadecimal buffer into a string (based on code from stack overflow)
 *
 * @param p_input_buffer Input bytes to be converted to string
 * @param p_output_buffer Output buffer with input buffer converted to ASCII
 * @param length Size of the input buffer
 * @return Pointer to output buffer (null terminated)
 */
const char * convert_to_hex(const uint8_t *p_input_buffer, int32_t length, char * p_output_buffer);

/**
 * @brief Compare received and calculated CRC32 of a command
 *
 * @param p_buffer Buffer containing the full command
 * @param length Number of bytes in p_buffer
 * @return true
 * @return false
 */
bool is_crc32_valid(const uint8_t *p_buffer, const uint32_t length);

/**
 * @brief Finalizes constructing a command adding its length and CRC32 fields
 * 
 * @param p_buffer Buffer containing the command
 * @param p_write_index [IN/OUT] write pointer
 */
void command_add_length_and_crc32(uint8_t *p_buffer, uint16_t *p_write_index);

/**
 * @brief Transmit command stored in p_buffer
 * 
 * @param socket Socket that will send the command
 * @param p_buffer Buffer containing the command
 * @param size Command size in bytes
 * @return true 
 * @return false 
 */
bool command_transfer(int socket, const uint8_t *p_buffer, const uint16_t size);


/**
 * @brief Receives bytes from socket into a buffer for further processing
 * 
 * @param socket_fd Socket to receive data from
 * @param p_buffer Buffer to store the data until a valid command is received
 * @param p_offset Offset to write into p_buffer
 * @param buffer_size Maximum size of p_buffer
 * @return operation_t 
 */
operation_t receive_data_stream(int socket_fd, uint8_t *p_buffer, size_t *p_offset, size_t buffer_size);

uint16_t payload_extract_length(const uint8_t *p_buffer);

#endif //COMMON_HEADER_
