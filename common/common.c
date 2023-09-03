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
#include "sha256.h"
#include "rabinpoly.h"
#include "commands_codes.h"
#include "crc32.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

// Buffer used to store Rabin sliced data (calculate SHA-256 fingerprint)
static uint8_t slice_buffer[RABIN_AVG_BLOCK_SIZE];

bool is_valid_ipv4(const char *p_ipv4)
{
   struct sockaddr_in addr = { 0 };

   return (1 == inet_pton(AF_INET, p_ipv4, &addr)) ? true : false;
}

bool file_exists(const char *p_file_name)
{
   struct stat file = { 0 };

   return (stat(p_file_name, &file) == 0);
}

void file_calculate_sha256_slice(FILE *file, long offset, uint16_t size, uint8_t *p_sha256_digest)
{
   // Inititalize a SHA256 context:
   SHA256_CTX sha256_context = {0};
   SHA256_init(&sha256_context);

   // Position the file cursor to the requested offset:
   fseek(file, offset, SEEK_SET);

   ssize_t bytes_remaining = size;
   ssize_t max_bytes_to_read = (bytes_remaining <= RABIN_AVG_BLOCK_SIZE) ? bytes_remaining : RABIN_AVG_BLOCK_SIZE;
   ssize_t bytes_read = 0;

   while ((bytes_read = fread(slice_buffer, sizeof(uint8_t), max_bytes_to_read, file)) > 0)
   {
      SHA256_update(&sha256_context, slice_buffer, bytes_read);

      bytes_remaining -= bytes_read;
      max_bytes_to_read = (bytes_remaining <= RABIN_AVG_BLOCK_SIZE) ? bytes_remaining : RABIN_AVG_BLOCK_SIZE;
   }

   const uint8_t *p_file_digest_calculated = SHA256_final(&sha256_context);

   memcpy(p_sha256_digest, p_file_digest_calculated, SHA256_DIGEST_SIZE);
}

void  file_calculate_sha256(const char *p_file_name, uint8_t *p_data_buffer, size_t size, uint8_t *p_sha256_digest)
{
   // Open the file in read only mode:
   FILE *file = fopen(p_file_name, "rb");

   // Inititalize SHA256 context:
   SHA256_CTX sha256_context = { 0 };
   SHA256_init(&sha256_context);

   size_t bytes_read = 0;

   while ((bytes_read = fread(p_data_buffer, sizeof(uint8_t), size, file)) > 0)
   {
      SHA256_update(&sha256_context, p_data_buffer, bytes_read);
   }

   fclose(file);

   const uint8_t *p_file_digest_calculated = SHA256_final(&sha256_context);

   memcpy(p_sha256_digest, p_file_digest_calculated, SHA256_DIGEST_SIZE);
}

// Based on: https://stackoverflow.com/a/53966346
const char * convert_to_hex(const uint8_t *p_input_buffer, int32_t length, char * p_output_buffer)
{
   const char hardcoded[] = "0123456789ABCDEF";

   const int32_t terminate = length;

   while(--length >= 0)
   {
      p_output_buffer[length] = hardcoded[(p_input_buffer[length >> 1] >> ((1 - ( length & 1)) << 2)) & 0xF];
   }

   p_output_buffer[terminate] = 0x00;

   return p_output_buffer;
}

uint16_t payload_extract_length(const uint8_t *p_buffer)
{
   // Extract lengtg info from the payload: 
   // Length includes: CMD + PAYLOAD (not include CRC32 bytes)
    uint16_t n_length = 0;
    memcpy(&n_length, &p_buffer[PROTOCOL_HEADER_LENGTH_INDEX], sizeof(uint16_t));
    return ntohs(n_length);
}

bool is_crc32_valid(const uint8_t *p_buffer, const uint32_t length)
{
   const uint32_t crc_index = length - sizeof(uint32_t);

   uint32_t n_crc32 = 0;
   memcpy(&n_crc32, &p_buffer[crc_index], sizeof(uint32_t));
 
   const uint32_t received_crc32 = ntohl(n_crc32);
   const uint32_t calculated_crc32 = crc32(p_buffer, crc_index, 0u);

    return (calculated_crc32 == received_crc32);
}

void command_add_length_and_crc32(uint8_t *p_buffer, uint16_t *p_write_index)
{
   uint32_t write_index = *p_write_index;

   // Populate correct protocol length: CMD + PAYLOAD
   const uint16_t cmd_length = htons(sizeof(uint8_t) + (write_index - PROTOCOL_START_PAYLOAD_INDEX)); // CMD + PAYLOAD AREA (not include CRC32)
   memcpy(&p_buffer[PROTOCOL_HEADER_LENGTH_INDEX], &cmd_length, sizeof(cmd_length));

   // Calculate CRC32:
   const uint32_t cmd_crc32 = htonl(crc32(p_buffer, write_index, 0u));
   memcpy(&p_buffer[write_index], &cmd_crc32, sizeof(cmd_crc32));

   write_index += sizeof(cmd_crc32);

   *p_write_index = write_index;
}

bool command_transfer(int socket, const uint8_t *p_buffer, const uint16_t size)
{
    uint8_t retries = 3u;
    ssize_t remaining_bytes = size;

    do
    {
        const ssize_t bytes_sent = send(socket, p_buffer, remaining_bytes, 0);

        if (-1 == bytes_sent)
        {
            break;
        }

        p_buffer += bytes_sent;
        remaining_bytes -= bytes_sent;

    } while ((remaining_bytes > 0) && retries);

    return (0 == remaining_bytes);
}

operation_t receive_data_stream(int socket_fd, uint8_t *p_buffer, size_t *p_offset, size_t *p_extra_bytes, size_t buffer_size)
{
    // Receives data until a complete command is received from the server
    // Need to deal with partial commands that were segmented by TCP stack

    operation_t operation = RECEIVED_CMD_ERROR;

    const ssize_t received_bytes = recv(socket_fd, p_buffer + *p_offset, buffer_size - *p_offset, 0);

    if (0 == received_bytes)
    {
        // Socket was disconnected by server:
        return SOCKET_DISCONNECTED_BY_PEER;
    }

    if (-1 == received_bytes)
    {
        return RECEIVED_CMD_ERROR;
    }

    // Update number of bytes received:
    *p_offset += received_bytes;

    // Verify if a full command was received:
    const uint8_t header_a = p_buffer[PROTOCOL_HEADER_BYTE_A_INDEX];
    const uint8_t header_b = p_buffer[PROTOCOL_HEADER_BYTE_B_INDEX];

    // Read expected command length:
    // Length includes: CMD_BYTE + PAYLOAD only (CRC32 is not included)
    uint16_t n_length = 0;
    memcpy(&n_length, &p_buffer[PROTOCOL_HEADER_LENGTH_INDEX], sizeof(n_length));
    const uint16_t length = ntohs(n_length);

    if ((header_a != PROTOCOL_HEADER_BYTE_A) || (header_b != PROTOCOL_HEADER_BYTE_B))
    {
        operation = RECEIVED_CMD_ERROR;
    }
    else
    {
        const size_t full_command_size = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + length + sizeof(uint32_t);

        if (full_command_size <= *p_offset)
        {
            // A full command was received now verify its CRC:
            operation = is_crc32_valid(p_buffer, full_command_size) ? RECEIVED_CMD_FULL : RECEIVED_CMD_ERROR;

            *p_extra_bytes = *p_offset - full_command_size;
        }      
        else
        {
            // A command was received partially, continue receiving data:
            operation = RECEIVED_CMD_PARTIAL;
        }
    }

    return operation;
}
