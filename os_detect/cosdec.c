#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to run a shell command and return the output
char* run_command(const char *command) {
    FILE *fp;
    char *result = malloc(1024);  // Allocate memory for the result
    char temp[128];
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command\n");
        free(result);
        return NULL;
    }

    // Read command output
    while (fgets(temp, sizeof(temp), fp) != NULL) {
        strcat(result, temp);
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
