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

typedef enum
{
    SERVER_READY_CMD = 0x00,                // Server to Client (after client`s connection was established and a worker thread is available to process it)

    REQUEST_FILE_STS_CMD,                       // Client to Server: Client will request file information from server side
    REQUEST_FILE_STS_SERVER_RESPONSE_CMD,       // Server to Client: Server side will

    REQUEST_FILE_TRANSFER_CMD,                  // Client to server: Sending Rabin fingerprint or requesting the whole file to be transferred.
    REQUEST_FILE_TRANSFER_SERVER_RESPONSE_CMD   // Server to client: Server will send diffs based on Rabin fingerprints or the whole file to the client.

} command_t;

// Auxiliary constants manage the 'REQUEST_FILE_STS_CMD':
#define FILE_DOES_NOT_EXIST_ON_SERVER               (0x00)
#define FILE_EXIST_ON_SERVER_WITH_SAME_HASH         (0x01)
#define FILE_EXIST_ON_SERVER_WITH_DIFFERENT_HASH    (0x02)

// Auxiliary constants to manage the 'REQUEST_FILE_STS_CMD':
#define FILE_STATUS_NO_HASH                         (0x00)
#define FILE_STATUS_WITH_HASH                       (0x01)

// Auxiliary constants to manage the 'REQUEST_FILE_TRANSFER_CMD';
#define REQUEST_FILE_WITHOUT_RABIN                  (0x00)
#define REQUEST_FILE_WITH_RABIN_UPDATE              (0x01)
#define REQUEST_FILE_WITH_RABIN_FINISH              (0x02)


// Auxiliary constants to manage the 'REQUEST_FILE_TRANSFER_SERVER_RESPONSE_CMD';
#define FILE_TRANSFER_UPDATE                        (0x00)
#define FILE_TRANSFER_FINISH                        (0x01)



// Command format:
// 0xAA 0x55 L1 L2 CMD <PAYLOAD> CRC32
// Where:
// 0xAA and 0x55 protocol header
// L1 L2: 16 bits length which contains CMD + <PAYLOAD> (does not include CRC32)
// CRC32: 32 bits

#define PROTOCOL_HEADER_BYTE_A_INDEX    (0x00)
#define PROTOCOL_HEADER_BYTE_B_INDEX    (0x01)
#define PROTOCOL_HEADER_LENGTH_INDEX    (0x02)
#define PROTOCOL_HEADER_CMD_INDEX       (0x04)
#define PROTOCOL_START_PAYLOAD_INDEX    (0x05)

#define PROTOCOL_HEADER_BYTE_A          (0xAA)
#define PROTOCOL_HEADER_BYTE_B          (0x55)