#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_BUFFER_SIZE 1024

// Function to run a shell command and return the output
char* run_command(const char *command) {
    FILE *fp;
    size_t buffer_size = INITIAL_BUFFER_SIZE;
    size_t len = 0;
    char *result = malloc(buffer_size);  // Allocate memory for the result
    char temp[128];

    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    result[0] = '\0';  // Initialize the result buffer to an empty string

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to execute nmap command");
        free(result);
        return NULL;
    }

    // Read command output
    while (fgets(temp, sizeof(temp), fp) != NULL) {
        size_t temp_len = strlen(temp);

        // If there's not enough space in the buffer, resize it
        if (len + temp_len >= buffer_size) {
            buffer_size *= 2;  // Double the buffer size
            char *new_result = realloc(result, buffer_size);
            if (new_result == NULL) {
                fprintf(stderr, "Memory reallocation failed\n");
                fclose(fp);
                free(result);
                return NULL;
            }
            result = new_result;  // Point to the new memory
        }

        strcat(result, temp);
        len += temp_len;
    }

    fclose(fp);
    return result;
}

// Function to extract OS information from nmap output
void extract_os_info(char *nmap_output) {
    char *os_start = strstr(nmap_output, "OS details:");
    if (os_start) {
        os_start += strlen("OS details:");  // Move to the actual OS info
        char *os_end = strstr(os_start, "\n");
        if (os_end) {
            *os_end = '\0';  // Null terminate the OS string
        }
        printf("Operating System: %s\n", os_start);
    } else {
        printf("Operating System: OS detection failed\n");
    }
}

// Function to scan the network and display device information
void scan_network(const char *network_range) {
    char command[256];
    snprintf(command, sizeof(command), "nmap -O %s", network_range);  // nmap -O for OS detection

    // Run nmap and capture its output
    char *nmap_output = run_command(command);
    if (nmap_output == NULL) {
        printf("Failed to execute nmap command.\n");
        return;
    }

    // Print the nmap scan results
    printf("Scanning network: %s\n", network_range);
    printf("Nmap Output:\n%s\n", nmap_output);

    // Extract and print OS info from nmap output
    extract_os_info(nmap_output);

    free(nmap_output);  // Free the allocated memory
}

int main() {
    // Define the network range to scan (e.g., 192.168.1.0/24 for a local network)
    const char *network_range = "192.168.1.0/24";

    // Scan the network and display device information
    scan_network(network_range);

    return 0;
}
