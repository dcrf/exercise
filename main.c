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
#include "client.h"


// Auxiliary functions to sanity check user inputs:
static app_mode_t app_identify_running_mode(int argc, char *argv[]);
static long int convert_port_string_to_numeric(const char *p_port_value);
static void app_print_helper_message(void);
static void signal_handler(int signal);

// Auxiliary constants to sanity check user inputs:
#define APP_OPERATION_MODE_INDEX    (1)
#define APP_USER_MIN_ARGUMENTS      (3)     // network server 23456
#define APP_SERVER_MIN_PORT_VALUE   (1024)  // First 1024 ports are reserved for Admin services

// Client mode auxiliary constants:
#define APP_CLIENT_NUMBER_ARGUMENTS (5)    // network client 192.168.10.23 3456 file.txt
#define APP_CLIENT_IP_INDEX         (2)
#define APP_CLIENT_PORT_INDEX       (3)
#define APP_CLIENT_FILENAME_INDEX   (4)

// Server mode auxiliary constant:
#define APP_SERVER_PORT_INDEX       (2)    // network server 23456

/**
 * @brief Used to request the application to shutdown itself
 *        All allocated resources will be freed and/or closed.
 * 
 */
static volatile bool app_run = true;

int main(int argc, char **argv)
{
    const app_mode_t app_mode = app_identify_running_mode(argc, argv);

    if (APP_UNKNOWN_MODE == app_mode)
    {
        app_print_helper_message();
        exit(-1);
    }

    // Register signal infra-structure to let the user gracefully request an application shutdown:
    signal(SIGINT, signal_handler);

    int32_t result = -1;

    if (APP_CLIENT_MODE == app_mode)
    {
        const char *p_ip    = argv[APP_CLIENT_IP_INDEX];
        const char *p_port  = argv[APP_CLIENT_PORT_INDEX];
        const char *p_file  = argv[APP_CLIENT_FILENAME_INDEX];        
        
        result = run_application_in_client_mode(p_ip, p_port, p_file, &app_run);
    }
    else if (APP_SERVER_MODE == app_mode)
    {
        // This function will return only:
        // a) When CTRL + C was intercepted to gracefully shutdown the application in server mode       

        //const char *p_port = argv[APP_SERVER_PORT_INDEX];
        //run_application_in_server_mode(p_port, &app_run);
    }

    if (false == app_run)
    {
        printf("\r\nThe user requested to shutdown the %s application.\r\n", (app_mode == APP_CLIENT_MODE) ? "CLIENT" : "SERVER");
    }
    
    return result;
}

/**
 * @brief Identify which mode the application is running (client or server)
 * 
 * @param argc Number of arguments supplied by command line
 * @param argv Pointer to a buffer of strings supplied by command line
 * @return app_mode_t Application mode sanity checked
 */
static app_mode_t app_identify_running_mode(int argc, char *argv[])
{
    app_mode_t mode = APP_UNKNOWN_MODE;    

    if (argc < APP_USER_MIN_ARGUMENTS)
    {
        return mode;
    }

    if ((APP_CLIENT_NUMBER_ARGUMENTS == argc) && 
        (strcmp("client", argv[APP_OPERATION_MODE_INDEX]) == 0))
    {
        // Validate the IPv4 address supplied by the user:
        const char *p_ip_address = argv[APP_CLIENT_IP_INDEX];
        
        if (!is_valid_ipv4(p_ip_address))
        {
            printf("\r\nThe Ipv4 [%s] is invalid", p_ip_address);
            return mode;
        }

        // Validate the port supplied by the user:
        const char *p_port = argv[APP_CLIENT_PORT_INDEX];
        const long port = convert_port_string_to_numeric(p_port);

        mode = (port <= APP_SERVER_MIN_PORT_VALUE) ? APP_UNKNOWN_MODE : APP_CLIENT_MODE;       
    }
    else if (strcmp("server", argv[APP_OPERATION_MODE_INDEX]) == 0)
    {
        // Validate the port supplied by the user:
        const char *p_port = argv[APP_SERVER_PORT_INDEX];
        const long port = convert_port_string_to_numeric(p_port);

        mode = (port <= APP_SERVER_MIN_PORT_VALUE) ? APP_UNKNOWN_MODE : APP_SERVER_MODE;        
    }
    else
    {
        mode = APP_UNKNOWN_MODE;
    }

    return mode;    
}

/**
 * @brief Signal handler to control the application shutdown
 * 
 * @param signal Signal intercepted by the application
 */
static void signal_handler(int signal)
{
    if (SIGINT == signal)
    {
        // User sent a CTRL+C
        // Start the application shutdown process.

        app_run = false;
    }
}

/**
 * @brief Convert a port value string into a numeric value
 * 
 * @param p_port_value ASCII port value
 * @return long int Port value converted to decimal number
 */
static long int convert_port_string_to_numeric(const char *p_port_value)
{
    char *p_end = NULL;
    const long int port = strtol(p_port_value, &p_end, 10);

    if (port < APP_SERVER_MIN_PORT_VALUE)
    {
        printf("\r\nThe port value [%ld] is invalid. It should be greater than %d", port, APP_SERVER_MIN_PORT_VALUE);        
    }

    return port;
}

/**
 * @brief Auxiliary function to print a helper message if the command line arguments were not correct
 * 
 */
static void app_print_helper_message(void)
{
    printf("\r\n");
    printf("Usage:\r\n");
    printf("\r\nRunning in client mode:\r\n");    
    printf("\tnetwork client <server ipv4> <server port> <file name>\r\n");
    printf("\tExample: network client 192.168.1.20 25000 music.txt\r\n");
    printf("\r\n");
    printf("\r\nRunning in server mode:\r\n");
    printf("\tnetwork server <listening port> - Where port value shall be larger than 1025\r\n");
    printf("\tExample: network server 25000\r\n");
}