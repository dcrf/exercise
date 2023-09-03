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
#include "sha256.h"
#include "commands_codes.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#undef SERVER_DBG

/**
 * @brief Server context variable
 * 
 */
typedef struct
{
    volatile bool *p_run;
    const char *p_server_port;
    threadpool pool;
    size_t max_number_of_worker_threads;
    size_t max_number_of_connections;
    int listening_socket;
} server_app_ctx;

/**
 * @brief Server worker thread file transfer context
 * 
 */
typedef struct server
{
    FILE *p_file_stream;
    FILE *p_auxiliar_file;
    uint8_t *p_buffer;
    size_t buffer_size;
    size_t buffer_receive_offset;
    size_t extra_bytes;
    struct pollfd fds[1];
    operation_t operation;
    uint8_t file_sha256_hash[SHA256_DIGEST_SIZE];
    char file_name[FILE_NAME_MAX_STRING_SIZE + 1u];
    int socket;
} file_transfer_ctx;


// Private auxiliary functions:
static void cleanup(void);
static int create_listening_socket(void);
static int32_t server_process_clients(void);
static void file_transfer_worker_function(int client_socket);
static void server_send_ready_message(int client_socket, uint8_t *p_buffer);
static void process_request_file_sts_cmd(file_transfer_ctx *p_ctx);
static operation_t process_full_command(file_transfer_ctx *p_ctx);
static void process_request_file_transfer_cmd(file_transfer_ctx *p_ctx);
static void server_sends_whole_file_no_fingerprints(file_transfer_ctx *p_ctx);

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
                            #ifdef SERVER_DBG
                                printf("\r\nAdding socket client into worker pool");
                            #endif

                            thpool_add_work(server.pool, file_transfer_worker_function, client_socket);
                        }
                        else
                        {
                            // Unfortunately we have no more available jobs on the queue to store this new client:
                            #ifdef SERVER_DBG
                                printf("\r\nCancelling client connection. No more resources available");
                            #endif

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

static void file_transfer_worker_function(int client_socket)
{
    int32_t result = -1;

    file_transfer_ctx ctx = {0};
    memset(&ctx, 0x00, sizeof(ctx));

    uint8_t client_buffer[RABIN_MAX_BLOCK_SIZE + 64u];

    ctx.p_buffer = client_buffer;
    ctx.buffer_size = RABIN_MAX_BLOCK_SIZE;
    ctx.socket = client_socket;

    ctx.fds[0].fd = ctx.socket;
    ctx.fds[0].events = POLLIN | POLLERR | POLLHUP;

    const int socket_timeout_ms = 5000;

    // Server triggers client that it can start the file process request:
    server_send_ready_message(ctx.socket, ctx.p_buffer);

    while (*server.p_run)
    {
        // Timeout every 5s to give a chance to "client.p_run" being evaluated
        result = poll(ctx.fds, 1, socket_timeout_ms);

        const short revents = ctx.fds[0].revents;

        if (0 == result)
        {
            // Client socket has timed-out:
        }
        else
        {
            if (revents & POLLIN)
            {
                // Server has data to read from client`s socket:
                ctx.operation = receive_data_stream(ctx.socket, ctx.p_buffer, &ctx.buffer_receive_offset, &ctx.extra_bytes, ctx.buffer_size);

                if (ctx.operation == RECEIVED_CMD_FULL)
                {
                    ctx.operation = process_full_command(&ctx);
                }
                else if (ctx.operation == RECEIVED_CMD_ERROR)
                {
                    // Resets buffer to start receiving a new command:
                    ctx.buffer_receive_offset = 0;
                }
                else if (ctx.operation == RECEIVED_CMD_PARTIAL)
                {
                    // Continue receiving data
                }
                else if (ctx.operation == SOCKET_DISCONNECTED_BY_PEER)
                {
                    #ifdef SERVER_DBG
                        printf("\r\nClient socket %d was disconnected", ctx.socket);
                        printf("\r\nCancelling file operation for client - %d\r\n", ctx.socket);
                    #endif
                    result = -1;
                    break;
                }
            }
        }
    }

#ifdef SERVER_DBG
    printf("\r\nFinishing client file transfer - %d", ctx.socket);
    fflush(stdout);
#endif

    shutdown(ctx.socket, SHUT_RDWR);
    close(ctx.socket);
}

static operation_t process_full_command(file_transfer_ctx *p_ctx)
{
    // Here we have a full command received from the client
    // The command was sanity checked: protocol headers and CRC32.

    // The protocol between client and server is very simple to make each command 'self-contained' in terms of
    // processing and consequenct actions.
    // The server will analyse the command received and start its consequent actions.

    operation_t next_operation = START_RECEIVING_CMD;

    // Reads command received:
    const uint8_t command = p_ctx->p_buffer[PROTOCOL_HEADER_CMD_INDEX];

    switch (command)
    {
        // This command is received by the server when the client side requests information about a specific file
        // The server side will verify if:
        // 1. File exists
        // 2. If exists and have same or different contents based on its SHA256 digest
        // 3. Send a response back to client with the file status
        
        case (REQUEST_FILE_STS_CMD):
            process_request_file_sts_cmd(p_ctx);
            break;

        // This command is received by the server when client is sending a request to update a file
        // The client can request a file transfer based on Rabin fingerprints or a full file transfer.
        case (REQUEST_FILE_TRANSFER_CMD):
            process_request_file_transfer_cmd(p_ctx);
            break;
#if 0

        // Todo: Missing Rabin fingerprint processing
        //       Application is segfaulting during a fwrite operation when receiving the whole data (for file > 1Mbyte)

#endif            

        default:
            break;
    }

    p_ctx->buffer_receive_offset = 0;

    return next_operation;
}

static void process_request_file_transfer_cmd(file_transfer_ctx *p_ctx)
{
    // The command option will tell server if client is sending Rabin fingerprints or requesting a full file tranfer:
    const uint8_t command_option = p_ctx->p_buffer[PROTOCOL_START_PAYLOAD_INDEX];

    if (REQUEST_FILE_WITHOUT_RABIN == command_option)
    {
        // Send the whole local file into segments
        // Each segment will be transferred using the format: offset (32 bits), length (16 bits), payload (lenght bytes)
        // The last segment will contain a special command_option to let client side aware that the transmission has finised.
        server_sends_whole_file_no_fingerprints(p_ctx);
    }
}

static void server_sends_whole_file_no_fingerprints(file_transfer_ctx *p_ctx)
{
    if (NULL == p_ctx->p_file_stream)
    {
        // Open local file in read-only binary mode:
        p_ctx->p_file_stream = fopen(p_ctx->file_name, "rb");
    }

    uint32_t slice_offset = 0u;

    do
    {
        uint16_t write_index = 0;

        p_ctx->p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_A;
        p_ctx->p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_B;

        write_index += 2u; // Skip slot for 16 bits length

        p_ctx->p_buffer[write_index++] = REQUEST_FILE_TRANSFER_SERVER_RESPONSE_CMD;

        // This option needs to be changed to 'FILE_TRANSFER_FINISH' in case this is the last command being sent to client:
        p_ctx->p_buffer[write_index++] = FILE_TRANSFER_UPDATE;

        size_t available_payload = p_ctx->buffer_size; // Buffer has extra space for protocol overhead and crc32

        // Available payload must have space for a segment of at least one byte: offset, lenght, payload
        while(available_payload >= (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t)))
        {
            uint8_t *p_offset = &p_ctx->p_buffer[write_index];
            uint8_t *p_length = &p_ctx->p_buffer[write_index + sizeof(uint32_t)];
            uint8_t *p_slice  = &p_ctx->p_buffer[write_index + sizeof(uint32_t) + sizeof(uint16_t)];

            // Discard the space needed by the offset and lenght fields:
            available_payload -= (sizeof(uint32_t) + sizeof(uint16_t));

            // Read a slice of data from local file into memory buffer:
            const size_t bytes_read = fread(p_slice, sizeof(uint8_t), available_payload, p_ctx->p_file_stream);
            
            if (bytes_read)
            {
                // Advance write_index because a new segment was added into the payload:
                write_index += (sizeof(uint32_t) + sizeof(uint16_t));

                const uint32_t n_offset = htonl(slice_offset);
                memcpy(p_offset, &n_offset, sizeof(n_offset));

                const uint16_t n_length = htons(bytes_read);
                memcpy(p_length, &n_length, sizeof(n_length));

                // For next interaction
                slice_offset += bytes_read;
                write_index += bytes_read;
                available_payload -= bytes_read;
            }
            else
            {
                // Finish reading data from file:
                // This is the last update command sent to client
                p_ctx->p_buffer[PROTOCOL_START_PAYLOAD_INDEX] = FILE_TRANSFER_FINISH;
                break;
            }
        }

        command_add_length_and_crc32(p_ctx->p_buffer, &write_index);
        command_transfer(p_ctx->socket, p_ctx->p_buffer, write_index);

    } while (p_ctx->p_buffer[PROTOCOL_START_PAYLOAD_INDEX] == FILE_TRANSFER_UPDATE);
}

static void process_request_file_sts_cmd(file_transfer_ctx *p_ctx)
{
    // Extract command lenght info: CMD + PAYLOAD
    const uint16_t length = payload_extract_length(p_ctx->p_buffer);

    uint16_t offset_read = PROTOCOL_START_PAYLOAD_INDEX + 1u;

    uint8_t remote_file_digest[SHA256_DIGEST_SIZE];
    memset(remote_file_digest, 0x00, SHA256_DIGEST_SIZE);

    // The command option carries information if client has included SHA-256 info in the payload:
    const uint8_t command_option = p_ctx->p_buffer[PROTOCOL_START_PAYLOAD_INDEX];

    uint16_t file_name_size = length - sizeof(uint8_t) - sizeof(uint8_t);
    
    if (FILE_STATUS_WITH_HASH == command_option)
    {
        // Next 32 bytes contains SHA256 of client file:
        memcpy(remote_file_digest, &p_ctx->p_buffer[offset_read], SHA256_DIGEST_SIZE);
        offset_read += SHA256_DIGEST_SIZE;

        file_name_size -= SHA256_DIGEST_SIZE;
    }

    // Copy client file name starting at 'offset_read':
    file_name_size = (file_name_size <= FILE_NAME_MAX_STRING_SIZE) ? file_name_size : FILE_NAME_MAX_STRING_SIZE;
    memcpy(p_ctx->file_name, &p_ctx->p_buffer[offset_read], file_name_size);
    p_ctx->file_name[FILE_NAME_MAX_STRING_SIZE] = 0x00;

    // First sanity-check: Verify if the file exists on the server folder:
    const bool is_file_present = file_exists(p_ctx->file_name);

    // Second sanity-check: If file exists locally calculate its SHA-256 digest:
    if (is_file_present)
    {
        // It is fine here to reuse the same 'ctx->p_buffer' that contains the received command
        // All important information was already extracted and stored.
        file_calculate_sha256(p_ctx->file_name, p_ctx->p_buffer, p_ctx->buffer_size, p_ctx->file_sha256_hash);
    }

    // Here prepare the response command back to the client:
    uint16_t write_index = 0;

    p_ctx->p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_A;
    p_ctx->p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_B;

    write_index += 2u; // Skip slot for the 16 bits length variable

    // Command code:
    p_ctx->p_buffer[write_index++] = REQUEST_FILE_STS_SERVER_RESPONSE_CMD;

    // Prepare command sub-option:
    uint8_t sub_option;

    if (!is_file_present)
    {
        sub_option = FILE_DOES_NOT_EXIST_ON_SERVER;
    }
    else
    {
        if (0 == memcmp(p_ctx->file_sha256_hash, remote_file_digest, SHA256_DIGEST_SIZE))
        {
            // Remote and local files have same contents:
            sub_option = FILE_EXIST_ON_SERVER_WITH_SAME_HASH;
        }
        else
        {
            // Remote and local files have different contents:
            sub_option = FILE_EXIST_ON_SERVER_WITH_DIFFERENT_HASH;
        }
    }
    
    p_ctx->p_buffer[write_index++] = sub_option;

    command_add_length_and_crc32(p_ctx->p_buffer, &write_index);
    command_transfer(p_ctx->socket, p_ctx->p_buffer, write_index);
}

static void server_send_ready_message(int client_socket, uint8_t *p_buffer)
{
    // Constructs a 'SERVER_READY_CMD' command:
    uint16_t write_index = 0;

    p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_A;
    p_buffer[write_index++] = PROTOCOL_HEADER_BYTE_B;

    write_index += 2u; // Skip slot for the 16 bits length variable

    // Specify 'SERVER_READY_CMD' to send to server:
    p_buffer[write_index++] = SERVER_READY_CMD;

    command_add_length_and_crc32(p_buffer, &write_index);
    command_transfer(client_socket, p_buffer, write_index);
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