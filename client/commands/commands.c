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

#include "commands.h"
#include "commands_codes.h"
#include "common.h"
#include "crc32.h"

#include <arpa/inet.h>


client_file_opt_t process_command_received(const uint8_t *p_buffer, uint32_t length)
{
    const uint8_t command = p_buffer[PROTOCOL_CMD_INDEX];

    switch (command)
    {
        case ()
    }



}