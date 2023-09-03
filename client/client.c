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
#include "rabinpoly.h"
#include "crc32.h"
#include "commands_codes.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>

#define CLIENT_DBG
#define CLIENT_CONNECT_RETRIES          (3)
#define CLIENT_COMMUNICATION_TIMEOUT_MS (90000)

// Generic buffer used to receive, transmit and generic operations:
static uint8_t command_buffer[RABIN_MAX_BLOCK_SIZE + 64u] = { 0 };

// Auxiliary buffer for debug purposes:
#ifdef CLIENT_DBG
static char debug_buffer[128u] = { 0 };
#endif

/**
 * @brief Auxiliary steps to drive client`s FSM
 *
 */
typedef enum
{
    CLIENT_START_RECEIVING_CMD = 0,
    CLIENT_RECEIVED_CMD_ERROR,
    CLIENT_RECEIVED_CMD_PARTIAL,
    CLIENT_RECEIVED_CMD_FULL,
    CLIENT_RECEIVED_FULL_FILE
} client_file_op_t;

/**
 * @brief Auxiliary struct to store Rabin fingerprint blocks
 *
 */
typedef struct
{
    uint32_t offset;
    uint16_t length;
    uint8_t fingerprint[SHA256_DIGEST_SIZE];
} rabin_slice_t;

/**
 * @brief Client context structure
 *
 */
typedef struct
{
    volatile bool *p_run;
    const char *p_server_ipv4;
    const char *p_server_port;
    const char *p_file_name;
    uint8_t *p_buffer;
    RabinPoly *p_rabin_ctx;
    FILE *p_file_stream;
    FILE *p_auxiliar_file;
    size_t buffer_size;
    size_t buffer_receive_offset;
    client_file_op_t operation;
    bool file_exists;
    uint8_t file_sha256_hash[SHA256_DIGEST_SIZE];
    int socket;
} client_app_ctx;

// Auxiliary local functions:
static void cleanup(void);
static void initialize_rabin_context(void);
static void finalize_command_adding_length_and_crc32(uint16_t *p_write_index);
static void update_local_file_with_data_received(void);
static void process_server_ready_cmd(void);
static void client_request_whole_file_without_rabin_fingerprints(void);
static void client_request_file_diff_using_rabin_fingerprints(void);
static bool rabin_get_next_block(rabin_slice_t *p_slice);
static bool client_transmit_to_server(int socket, const uint8_t *p_buffer, const uint32_t size);
static client_file_op_t receive_data_stream(void);
static client_file_op_t process_full_command(void);
static client_file_op_t process_file_transfer_from_server_cmd(void);
static client_file_op_t process_request_file_status_server_response_cmd(void);
static int32_t connect_with_remote_server(void);
static int32_t process_file_transfer(void);


// Client file transfer context variable:
static client_app_ctx client = { 0 };

// This function will return after one of these conditions are true:
// a) A CTRL + C was intercepted to exit the application.
// b) The requested file does not exist on the server.
// c) The local and requested files are the same.
// d) The requested file was transferred from server to client.
// e) No response (connect/send/receive) from the server after 90s.

int32_t run_application_in_client_mode(const char *p_server_ipv4,
                                       const char *p_server_port,
                                       const char *p_file_name,
                                       volatile bool *p_run)
{
    int32_t result = -1;

    // Initialize client context control variable:

    client.p_buffer = command_buffer;
    client.buffer_size = sizeof(command_buffer);
    client.buffer_receive_offset = 0;

    client.p_file_stream = NULL;
    client.p_auxiliar_file = NULL;
    client.p_rabin_ctx = NULL;

    client.p_server_ipv4 = p_server_ipv4;
    client.p_server_port = p_server_port;
    client.p_file_name = p_file_name;
    client.p_run = p_run;

    client.socket = -1;

    memset(client.file_sha256_hash, 0x00, SHA256_DIGEST_SIZE);

    // Check if the requested file exists on client side:
    client.file_exists = file_exists(p_file_name);

    if (client.file_exists)
    {
        file_calculate_sha256(p_file_name, client.p_buffer, sizeof(command_buffer), client.file_sha256_hash);

        #if defined(CLIENT_DBG)
            printf("\r\nFile: %s - SHA-256 digest:%s\r\n", p_file_name, convert_to_hex(client.file_sha256_hash, SHA256_DIGEST_SIZE, debug_buffer));
        #endif
    }
    else
    {
        #if defined(CLIENT_DBG)
            printf("\r\nFile: %s does not exist in local folder\r\n", p_file_name);
        #endif
    }

    // Try to stablish a TCP connection with the remote server:
    result = connect_with_remote_server();

    if (0 != result)
    {
        cleanup();
        return result;
    }

    // Client application will return from the next function only when one of these conditions happens:
    //
    // a) The requested file does not exist on the server side.
    // b) Local and requested files are equal (no transfer required).
    // b) The requested file was properly updated:
    //  b.1) Using Rabin figerprints to update only file diff and save bandwidth
    //  b.2) Complete file transfer (file exist only on server)
    // c) The server does not respond the client for a period of 90s after any socket transaction
    // d) User has requested the application to exit (CTRL + C)

    result = process_file_transfer();

    // Deallocate internal resources before exiting client application:
    cleanup();

    return result;
}

static int32_t process_file_transfer(void)
{
    int32_t result = -1;

    struct pollfd pfds[1];
    memset(pfds, 0x00, sizeof(pfds));

    pfds[0].fd = client.socket;
    pfds[0].events = POLLIN | POLLERR | POLLHUP;

    const int socket_timeout_ms = 5000;
    int32_t timeout_counter = CLIENT_COMMUNICATION_TIMEOUT_MS / socket_timeout_ms;

    while ((*client.p_run) && (timeout_counter > 0) && (CLIENT_RECEIVED_FULL_FILE != client.operation))
    {
        // Timeout every 5s to give a chance to "client.p_run" being evaluated
        result = poll(pfds, 1, socket_timeout_ms);

        const short revents = pfds[0].revents;

        if (0 == result)
        {
            // Client socket has timed-out:
            --timeout_counter;
        }
        else
        {
            // Reload timeout counter:
            timeout_counter = CLIENT_COMMUNICATION_TIMEOUT_MS / socket_timeout_ms;

            if (revents & POLLIN)
            {
                // Socket is ready to receive data from server

                client.operation = receive_data_stream();

                if (client.operation == CLIENT_RECEIVED_CMD_FULL)
                {
                    client.operation = process_full_command();
                }
                else if (client.operation == CLIENT_RECEIVED_CMD_ERROR)
                {
                    // Resets buffer to start receiving a new command:
                    client.buffer_receive_offset = 0;
                }
                else if (client.operation == CLIENT_RECEIVED_CMD_PARTIAL)
                {
                    // Continue receiving data
                }
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

static client_file_op_t receive_data_stream(void)
{
    // Receives data until a complete command is received from the server
    // Need to deal with partial commands that were segmented by TCP stack

    client_file_op_t operation = CLIENT_RECEIVED_CMD_ERROR;

    const ssize_t received_bytes = recv(client.socket, client.p_buffer + client.buffer_receive_offset, client.buffer_size, 0);

    if (-1 == received_bytes)
    {
        return operation;
    }

    // Update number of bytes received:
    client.buffer_receive_offset = received_bytes;

    // Verify if a full command was received:
    const uint8_t header_a = client.p_buffer[PROTOCOL_HEADER_BYTE_A_INDEX];
    const uint8_t header_b = client.p_buffer[PROTOCOL_HEADER_BYTE_B_INDEX];

    // Read expected command length:
    // Length includes: CMD_BYTE + PAYLOAD only (CRC32 is not included)
    uint16_t n_length = 0;
    memcpy(&n_length, &client.p_buffer[PROTOCOL_HEADER_LENGTH_INDEX], sizeof(n_length));
    const uint16_t length = ntohs(n_length);

    if ((header_a != PROTOCOL_HEADER_BYTE_A) || (header_b != PROTOCOL_HEADER_BYTE_B))
    {
        operation = CLIENT_RECEIVED_CMD_ERROR;
    }
    else
    {
        const size_t full_command_size = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + length + sizeof(uint32_t);

        if (full_command_size <= client.buffer_receive_offset)
        {
            // A full command was received now verify its CRC:
            operation = is_crc32_valid(client.p_buffer, full_command_size) ? CLIENT_RECEIVED_CMD_FULL : CLIENT_RECEIVED_CMD_ERROR;
        }
        else
        {
            // A command was received partially, continue receiving data:
            operation = CLIENT_RECEIVED_CMD_PARTIAL;
        }
    }

    return operation;
}


static client_file_op_t process_full_command(void)
{
    // Here we have a full command received from the server side.
    // The command was sanity checked: protocol headers and CRC32.

    // The protocol between client and server is very simple to make each command 'self-contained' in terms of
    // processing and consequenct actions.
    // The client side will receive a response from the server and trigger its consequent actions.

    client_file_op_t next_operation;

    // Reads command received:
    const uint8_t command = client.p_buffer[PROTOCOL_HEADER_CMD_INDEX];

    switch (command)
    {
        // This command is received by the client application when the server application has a
        // working poll thread available to start processing our file transfer validation.
        // Afer processing the 'SERVER_READY_CMD' command the client side will send a 'REQUEST_FILE_STS_CMD' command to server.
        case (SERVER_READY_CMD):
            process_server_ready_cmd();
            break;

        // This command is received by the client application with the status of the requested file on the server side.
        // The client application will analyse the server response and choose its consequent actions:
        // 1. Do nothing. Requested file does not exist on server.
        // 2. Do nothing. Server and client files have the same contents (SHA256 digest)
        // 3. Client application will request a file transfer to the server using Rabin blocks to save bandwidth or request a whole file transfer.
        case (REQUEST_FILE_STS_SERVER_RESPONSE_CMD):
            next_operation = process_request_file_status_server_response_cmd();
            break;

        // This command is received by the client application with a sequence of data slices send by the server side
        // Each data slice can be a Rabin block to reduce bandwidth usage while updating the file, or a sequential
        // data transfer where all bytes from the file will be transferred from the server to the client side.
        // The client application will store the received slices into a temporary file (to avoid corrupting the original client file).
        // Once all the slices were received from the server the client will update its local file with data from its temporary file.
        // If Rabin fingerprints were used the temporary file should have only the data segments that are different between client and server`s file
        case (REQUEST_FILE_TRANSFER_SERVER_RESPONSE_CMD):
            next_operation = process_file_transfer_from_server_cmd();
            break;

        default:
            break;
    }

    client.buffer_receive_offset = 0;

    return next_operation;
}

static client_file_op_t process_file_transfer_from_server_cmd(void)
{
    // The client will receive a sequence of file data slices from the server side.
    // The data slices can be only the data segments that differs between the files or a a complete sequential file data transfer.
    // Both Rabin slices and complete data transfer slices will follow the same format:
    // offset (32 bits), length (16 bits), payload data (length bytes)


    // Using a random generic file to avoid corrupting local file during file transfer:
    if (client.p_auxiliar_file == NULL)
    {
        client.p_auxiliar_file = tmpfile();
    }

    // Process the received data from server:
    // 1. Can be diffs or the whole data being transferred
    // 2. For now it doesn`t matter which one is happening.
    // 3. After the server signals the client that the transfer has finished the client will process the data received to update the local file

    uint16_t n_length = 0;
    memcpy(&n_length, &client.p_buffer[PROTOCOL_HEADER_LENGTH_INDEX], sizeof(uint16_t));

    uint16_t total_bytes_to_write = ntohs(n_length);
    total_bytes_to_write -= 2u; // Discounts the CMD and CMD_OPTIONS bytes

    // Discounts the CMD_OPTIONS byte:
    uint16_t read_payload_offset = PROTOCOL_START_PAYLOAD_INDEX + 1u;

    // Save the received payload area (discounted the CMD_OPTION byte) into the temporary file:
    while (total_bytes_to_write)
    {
        const ssize_t bytes_written = fwrite(&client.p_buffer[read_payload_offset], sizeof(uint8_t), total_bytes_to_write, client.p_auxiliar_file);

        read_payload_offset += bytes_written;
        total_bytes_to_write -= bytes_written;
    };

    // Check if this was the last file slice received from server:

    client_file_op_t next_operation;
    const uint8_t transfer_type = client.p_buffer[PROTOCOL_START_PAYLOAD_INDEX];

    if (transfer_type == FILE_TRANSFER_FINISH)
    {
        // Server has finished transferring all its data
        // Update local file with the info received from server

        update_local_file_with_data_received();
        next_operation = CLIENT_RECEIVED_FULL_FILE;
    }
    else
    {
        // Keep receiving data from server
        next_operation = CLIENT_START_RECEIVING_CMD;
    }

    return next_operation;
}

static void update_local_file_with_data_received(void)
{
    // Check if local file is open to receive data received from server and stored in the auxiliar local temporary file:
    if (client.p_file_stream == NULL)
    {
        client.p_file_stream = fopen(client.p_file_name, "rw");
    }

    // Set both files cursos offset to first position:
    fseek(client.p_file_stream,   0, SEEK_SET);
    fseek(client.p_auxiliar_file, 0, SEEK_SET);

    // Step1: Read data from temporary file into a local buffer
    // Step2: Write data from this local buffer into local file
    // Step3: Repeat Step1 and Step2 untill all file was copied from buffer to final file

    for (;;)
    {
        // Read a data slice offset from auxiliar file:
        ssize_t bytes_read = fread(client.p_buffer, sizeof(uint8_t), sizeof(uint32_t), client.p_auxiliar_file);

        if (bytes_read == 0)
        {
            // We reached the end of the temporary file
            break;
        }

        uint32_t n_offset = 0;
        memcpy(&n_offset, client.p_buffer, sizeof(uint32_t));
        const uint32_t slice_offset = ntohl(n_offset);

        // Read a data slice length from auxiliar file:
        bytes_read = fread(client.p_buffer, sizeof(uint8_t), sizeof(uint16_t), client.p_auxiliar_file);

        uint16_t n_length = 0;
        memcpy(&n_length, client.p_buffer, sizeof(uint16_t));
        const ssize_t slice_length = ntohs(n_length);

        // Read a slice data from our temporary file into the local buffer:
        ssize_t remaining_bytes = slice_length;
        void *p_buffer = client.p_buffer;

        while (remaining_bytes)
        {
            bytes_read = fread(p_buffer, sizeof(uint8_t), remaining_bytes, client.p_auxiliar_file);

            remaining_bytes -= bytes_read;
            p_buffer += bytes_read;
        }

        // Write the slice data from local buffer into final local file destination:
        // Set local file cursor offset:
        fseek(client.p_file_stream, slice_offset, SEEK_SET);

        remaining_bytes = slice_length;
        p_buffer = client.p_buffer;

        while (remaining_bytes)
        {
            ssize_t bytes_written = fwrite(p_buffer, sizeof(uint8_t), remaining_bytes, client.p_file_stream);

            remaining_bytes -= bytes_written;
            p_buffer += bytes_written;
        }
    }

    // Files clean-up will happen inside cleanup() function
}

static client_file_op_t process_request_file_status_server_response_cmd(void)
{
    // This command is sent from the server to the client application and contains information about the file on the server side.
    // The client will analyse the response and choose its consequent actions:

    // Client will sanity-check if the requested file does not exist on the server or if their contents are the same:
    const uint8_t server_file_status = client.p_buffer[PROTOCOL_START_PAYLOAD_INDEX];

    client_file_op_t next_operation = CLIENT_START_RECEIVING_CMD;

    switch (server_file_status)
    {
        case (FILE_DOES_NOT_EXIST_ON_SERVER):
            printf("\r\nThe requested file %s does not exist on server side", client.p_file_name);
            printf("\r\nClient application will finish");
            next_operation = CLIENT_RECEIVED_FULL_FILE; // This operation will trigger the exit process.
            break;

        case (FILE_EXIST_ON_SERVER_WITH_SAME_HASH):
            printf("\r\nThe local and requested file %s have the same contents", client.p_file_name);
            printf("\r\nClient application will finish");
            next_operation = CLIENT_RECEIVED_FULL_FILE; // This operation will trigger the exit process.
            break;

        case (FILE_EXIST_ON_SERVER_WITH_DIFFERENT_HASH):

            if (client.file_exists)
            {
                printf("\r\nThe file %s will be updated using Rabin blocks", client.p_file_name);
                client_request_file_diff_using_rabin_fingerprints();
            }
            else
            {
                printf("\r\nThe file %s will be copied from server without using Rabin blocks", client.p_file_name);
                client_request_whole_file_without_rabin_fingerprints();
            }
            break;

        default:
            printf("\r\nReceived unexpected file status response from server side");
            break;
    };

    return next_operation;
}

static void client_request_file_diff_using_rabin_fingerprints(void)
{
    // The client application will transfer to the server application its file`s set of Rabin fingerprints
    // The last fingerprint command sent to the server will carry a special code to
    // indicate the fingerprints were all transmited and the server can start the process of sending the data diff`s back to the client side.

    // Each Rabin Fingerprint will follow this format when added into the command`s payload area:
    // offset (32 bits), length (16 bits), sha256 (32 bytes)

    // Initialize Rabin context:
    initialize_rabin_context();

    // Open local file in read-binary mode to calculate Rabin fingerprints:
    if (client.p_file_stream != NULL)
    {
        fclose(client.p_file_stream);
    }

    client.p_file_stream = fopen(client.p_file_name, "rb");

    // To keep control when the last Rabin fingerprint was added into the command payload area:
    bool rabin_has_next_block = true;

    while (rabin_has_next_block)
    {
        uint16_t write_index = 0u;

        client.p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_A;
        client.p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_B;

        client.p_buffer[write_index++] = REQUEST_FILE_TRANSFER_CMD;

        write_index += 2u; // Skip slot for 16 bits length

        // Add sub-command option 'REQUEST_FILE_WITH_RABIN_UPDATE'
        // The final command with the last fingerprints shall update this value to 'REQUEST_FILE_WITH_RABIN_FINISH'
        client.p_buffer[write_index++] = REQUEST_FILE_WITH_RABIN_UPDATE;

        // I prefer using this idiom instead of declaring a __packed__ struct
        const size_t rabin_entry_size = sizeof(uint32_t) + sizeof(uint16_t) + SHA256_DIGEST_SIZE;

        // This is the available payload area dedicated to add the fingerprints.
        // The extra space to store the protocol headers and CRC32 are discounted from this value.
        size_t available_payload_area = RABIN_MAX_BLOCK_SIZE;

        do
        {
            rabin_slice_t rabin_slice = {0};

            // Keep adding Rabin fingerprints until:
            // 1. The available payload area has no more space for a new Rabin slice.
            // 2. Rhere is no more fingerprints entries to be added in the payload.

            rabin_has_next_block = rabin_get_next_block(&rabin_slice);
            file_calculate_sha256_slice(client.p_file_stream, rabin_slice.offset, rabin_slice.length, rabin_slice.fingerprint);

            // Add Rabin Offset into payload area:
            const uint32_t offset = htonl(rabin_slice.offset);
            memcpy(&client.p_buffer[write_index], &offset, sizeof(offset));
            write_index += sizeof(offset);

            // Add Rabin length into payload area:
            const uint16_t length = htons(rabin_slice.length);
            memcpy(&client.p_buffer[write_index], &length, sizeof(length));
            write_index += sizeof(length);

            // Add Rabin fingerprint into payload area:
            memcpy(&client.p_buffer[write_index], rabin_slice.fingerprint, SHA256_DIGEST_SIZE);
            write_index += SHA256_DIGEST_SIZE;

            available_payload_area -= rabin_entry_size;

        } while ((available_payload_area >= rabin_entry_size) && (rabin_has_next_block));

        // No more available space or no more fingerprints to be added into the payload.
        // Send this command and sanity-check if there are more fingerprints to be sent.

        if (!rabin_has_next_block)
        {
            // This is the last Rabin update command.
            // Update the sub-command option to signal the server side that all fingerprints were transmitted
            // Server will trigger its logic to generate a diff file to send back to client:
            client.p_buffer[PROTOCOL_START_PAYLOAD_INDEX] = REQUEST_FILE_WITH_RABIN_FINISH;
        }

        finalize_command_adding_length_and_crc32(&write_index);
        client_transmit_to_server(client.socket, client.p_buffer, write_index);
    };
}

static void client_request_whole_file_without_rabin_fingerprints(void)
{
    // Construct command to request a complete file transfer without using Rabin blocks

    uint16_t write_index = 0u;

    client.p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_A;
    client.p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_B;

    client.p_buffer[write_index++] = REQUEST_FILE_TRANSFER_CMD;

    write_index += 2u; // Skip slot for 16 bits length

    // Add sub-command ption (first payload byte)
    client.p_buffer[write_index++] = REQUEST_FILE_WITHOUT_RABIN;

    finalize_command_adding_length_and_crc32(&write_index);

    client_transmit_to_server(client.socket, client.p_buffer, write_index);
}

static void process_server_ready_cmd(void)
{
    // After receiving this command from server the client side will ask if a specific file exists on the server side.
    // The following table explains the consequenct actions:
    //
    // FILE_EXISTS_ON_SERVER    FILE_EXISTS_ON_CLIENT       CONSEQUENT_ACTIONS
    //        0                          0                  --> None. There is no file on the server to update the client
    //        0                          1                  --> None. There is no file on the server to update the client
    //        1                          0                  --> Client will request a full file transfer without using Rabin blocks
    //        1                          1                  --> Two scenarions are possible:
    //                                                          1. Local and remote files have the same contents (same SHA-256 digest)
    //                                                             No file transfer will happen
    //                                                          2. Local and remote files have different contents (different SHA-256 digest)
    //                                                             Transfer file from server to client using Rabin blocks to save bandwidth


    // Construct command to request the file status on the server side and choose consequent actions:

    uint16_t write_index = 0u;

    client.p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_A;
    client.p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_B;

    // Specify 'REQUEST_FILE_STS_CMD' to send to server:
    client.p_buffer[write_index++] = REQUEST_FILE_STS_CMD;

    write_index += 2u; // Skip slot for the 16 bits length variable

    if (client.file_exists)
    {
        // Add a sub-command option (first payload byte) to let server side knows that the command being received contains the client`s file SHA-256:
        client.p_buffer[write_index++] = FILE_STATUS_WITH_HASH;

        // Adds the client file SHA-256 digest into the payload area:
        memcpy(&client.p_buffer[write_index], client.file_sha256_hash, SHA256_DIGEST_SIZE);

        write_index += SHA256_DIGEST_SIZE;
    }
    else
    {
        // Add a sub-command option (first payload byte) to let server side knows that the command being received has no SHA-256 digest:
        client.p_buffer[write_index++] = FILE_STATUS_NO_HASH;
    }

    // It is safe to use strlen because the client file name was was already sanitized in the main function:
    const size_t file_name_length = strlen(client.p_file_name);
    memcpy(&client.p_buffer[write_index], client.p_file_name, file_name_length);
    write_index += file_name_length;

    // Adds command length and CRC32:
    finalize_command_adding_length_and_crc32(&write_index);

    // Sends command to server side:
    client_transmit_to_server(client.socket, client.p_buffer, write_index);
}

static void finalize_command_adding_length_and_crc32(uint16_t *p_write_index)
{
    uint32_t write_index = *p_write_index;

    // Populate correct protocol length: CMD + PAYLOAD
    const uint16_t cmd_length = htons(sizeof(uint8_t) + (write_index - PROTOCOL_START_PAYLOAD_INDEX)); // CMD + PAYLOAD AREA (not include CRC32)
    memcpy(&client.p_buffer[PROTOCOL_HEADER_LENGTH_INDEX], &cmd_length, sizeof(cmd_length));

    // Calculate CRC32:
    const uint32_t cmd_crc32 = htonl(crc32(client.p_buffer, write_index, 0u));
    memcpy(&client.p_buffer[write_index], &cmd_crc32, sizeof(cmd_crc32));

    write_index += sizeof(cmd_crc32);

    *p_write_index = write_index;
}

static bool client_transmit_to_server(int socket, const uint8_t *p_buffer, const uint32_t size)
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

    // Try up to CLIENT_CONNECT_RETRIES times to establish a connection with remote server:
    for (int32_t i = 0; i < CLIENT_CONNECT_RETRIES; ++i)
    {
        result = connect(client.socket, p_result->ai_addr, p_result->ai_addrlen);

        if (0 == result)
        {
            printf("\r\nSuccessfully connected to remote server %s:%s\r\n", client.p_server_ipv4, client.p_server_port);
            break;
        }

        printf("\r\nFailed to connect to remote server address %s:%s", client.p_server_ipv4, client.p_server_port);
        printf("\r\nRetry in 1[s]");
        sleep(1u);
    }

    freeaddrinfo(p_result);

    return result;
}

static void initialize_rabin_context(void)
{
    // Using minimum possible value to reduce the size of block of dynamic memory allocated.
    // The drawback is a slighly increase in the processing time.
	const size_t buf_size = RABIN_MAX_BLOCK_SIZE * 2u;

    // One possible optimization would be:
    // a) Analyse the size of the file to be sliced
    // b) Create a table of optimal Rabin block sizes based on the file size
    // c) Our initialization function uses block sizes optimized for the file size (small, medium, large)

    if (NULL != client.p_rabin_ctx)
    {
        rp_free(client.p_rabin_ctx);
        client.p_rabin_ctx = NULL;
    }

    client.p_rabin_ctx = rp_new(RABIN_WINDOW_SIZE, RABIN_AVG_BLOCK_SIZE, RABIN_MIN_BLOCK_SIZE, RABIN_MAX_BLOCK_SIZE, buf_size);

    rp_from_file(client.p_rabin_ctx, client.p_file_name);
}

/**
 * @brief Returns a Rabin slice offset and length
 *
 * @param p_slice Rabin slice structure to be filled
 * @return true  There are more slices to be returned
 * @return false There are no more slices to be returned
 */
static bool rabin_get_next_block(rabin_slice_t *p_slice)
{
    const bool more_slices_to_process = (0 != rp_block_next(client.p_rabin_ctx)) ? false : true;

    p_slice->offset = (uint32_t)client.p_rabin_ctx->block_streampos;
    p_slice->length = (uint16_t)client.p_rabin_ctx->block_size;

#if defined(CLIENT_DBG)
    static size_t counter = 0;
    printf("\r\nRabin Slice[%zu] - Offset: %zu - Size: %zu", counter++, client.p_rabin_ctx->block_streampos, client.p_rabin_ctx->block_size);
#endif

    return more_slices_to_process;
}

static void cleanup(void)
{
    // Cleanup the mess before leaving the client application:
    if (NULL != client.p_rabin_ctx)
    {
        rp_free(client.p_rabin_ctx);
    }

    if (-1 != client.socket)
    {
        shutdown(client.socket, SHUT_RDWR);
        close(client.socket);
        client.socket = -1;
    }

    if (NULL != client.p_auxiliar_file)
    {
        fclose(client.p_auxiliar_file);
        client.p_auxiliar_file = NULL;
    }

    if (NULL != client.p_file_stream)
    {
        fflush(client.p_file_stream);
        fclose(client.p_file_stream);
        client.p_file_stream = NULL;
    }
}
