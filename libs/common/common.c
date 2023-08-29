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

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

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

bool file_calculate_sha256(const char *p_file_name, uint8_t *p_data_buffer, size_t size, uint8_t *p_sha256_digest)
{
   // Open the file in read only mode:   
   FILE *file = fopen(p_file_name, "r");

   if (!file)
   {
      return false;      
   }

   // Inititalize SHA256 context:
   SHA256_CTX sha256_context = { 0 };   
   SHA256_init(&sha256_context);

   size_t bytes_read = 0;

   while ((bytes_read = fread(p_data_buffer, sizeof(uint8_t), size, file)) > 0)
   {
      SHA256_update(&sha256_context, p_data_buffer, bytes_read);
   }

   const uint8_t *p_file_digest_calculated = SHA256_final(&sha256_context);
   
   memcpy(p_sha256_digest, p_file_digest_calculated, SHA256_DIGEST_SIZE);

   return true;
}
