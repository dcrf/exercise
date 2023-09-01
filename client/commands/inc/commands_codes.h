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


// Command format:
// 0xAA 0x55 L1 L2 CMD <PAYLOAD> CRC32
// Where:
// 0xAA and 0x55 protocol header
// L1 L2: 16 bits length which contains CMD + <PAYLOAD> (does not include CRC32)
// CRC32: 32 bits 

//                         HEADER_BYTE_A     HEADER_BYTE_B     HEADER_LENGTH          CRC32
#define PROTOCOL_OVERHEAD (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t))

#define PROTOCOL_HEADER_BYTE_A  (0xAA)
#define PROTOCOL_HEADER_BYTE_B  (0x55)

#define PROTOCOL_LENGTH_INDEX   (0x02)
#define PROTOCOL_CMD_INDEX      (0x04)

typedef enum 
{
    COMMAND_
}
