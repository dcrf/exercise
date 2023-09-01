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


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/**
 * @brief Validates if a "SERVER_READY_CMD" was received from server
 * 
 * @param p_buffer Buffer with received data
 * @param size Bytes received
 * @return true 
 * @return false 
 */
bool received_valid_server_ready_command(const uint8_t *p_buffer, const uint32_t size);