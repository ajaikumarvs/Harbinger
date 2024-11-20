#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>

#define TIMEOUT 1 // Default timeout in seconds
#define MAX_RESULT_LENGTH 100000 // Maximum length for storing results

// A struct to pass data to each thread (port, host, timeout, result)
typedef struct {
    char *host;
    int port;
    int timeout;
    char *result; // Store the result for each port scan
} scan_data_t;

// Function to save results to a file
void save_results_to_file(const char *hostname, int start_port, int end_port, int timeout, const char *results) {
    FILE *file = fopen("scan_results.txt", "a");
    if (file) {
        fprintf(file, "--- Scan Results for %s ---\n", hostname);
        fprintf(file, "Port range: %d - %d\n", start_port, end_port);
        fprintf(file, "Timeout: %d seconds\n", timeout);
        fprintf(file, "%s", results);
        fclose(file);
        printf("Results saved to scan_results.txt\n");
    } else {
        printf("Failed to open file for writing results.\n");
    }
}

// Function to scan a port (with non-blocking connect)
void *scan_port(void *arg) {
    scan_data_t *data = (scan_data_t *)arg;
    int sock;
    struct sockaddr_in server_addr;
    int result;
    char result_buffer[1024];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->port);
    server_addr.sin_addr.s_addr = inet_addr(data->host);

    // Set socket timeout (for receive timeout)
    struct timeval tv;
    tv.tv_sec = data->timeout;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Make the socket non-blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);

    // Try to connect (non-blocking)
    result = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    if (result < 0) {
        if (errno == EINPROGRESS) {
            // If EINPROGRESS is set, the connection is in progress
            fd_set write_fds;
            fd_set except_fds;
            struct timeval timeout;
            FD_ZERO(&write_fds);
            FD_ZERO(&except_fds);
            FD_SET(sock, &write_fds);
            FD_SET(sock, &except_fds);

            timeout.tv_sec = data->timeout;
            timeout.tv_usec = 0;

            // Use select to wait for the socket to be writable or timeout
            result = select(sock + 1, NULL, &write_fds, &except_fds, &timeout);
            if (result <= 0) {
                // Timeout or error
                snprintf(result_buffer, sizeof(result_buffer), "Port %d is closed on %s\n", data->port, data->host);
            } else {
                // Socket is writable, so the connection succeeded
                snprintf(result_buffer, sizeof(result_buffer), "Port %d is open on %s\n", data->port, data->host);
            }
        } else {
            // Connection failed
            snprintf(result_buffer, sizeof(result_buffer), "Port %d is closed on %s\n", data->port, data->host);
        }
    } else {
        // Connection succeeded immediately
        snprintf(result_buffer, sizeof(result_buffer), "Port %d is open on %s\n", data->port, data->host);
    }

    // Store the result in the struct
    data->result = strdup(result_buffer); // Allocate memory for result

    // Close the socket
    close(sock);

    return NULL;
}

// Main function to run the scanner
int main() {
    char hostname[256];
    int start_port, end_port, timeout = TIMEOUT;
    char save_results_choice;
    char *final_results; // Dynamically allocated string to hold all results

    // Get user input for scanning parameters
    printf("Enter target host (IP or domain): ");
    scanf("%s", hostname);

    printf("Enter start port: ");
    scanf("%d", &start_port);

    printf("Enter end port: ");
    scanf("%d", &end_port);

    printf("Enter timeout in seconds (default %d): ", TIMEOUT);
    scanf("%d", &timeout);

    // Allocate memory for final_results, starting with an initial size
    final_results = (char *)malloc(MAX_RESULT_LENGTH * sizeof(char));
    if (!final_results) {
        printf("Memory allocation failed\n");
        return 1;
    }
    final_results[0] = '\0'; // Initialize the string

    // Allocate memory for thread handles
    pthread_t threads[end_port - start_port + 1];
    scan_data_t scan_data[end_port - start_port + 1];

    // Start scanning ports
    for (int port = start_port; port <= end_port; port++) {
        scan_data[port - start_port].host = hostname;
        scan_data[port - start_port].port = port;
        scan_data[port - start_port].timeout = timeout;

        if (pthread_create(&threads[port - start_port], NULL, scan_port, &scan_data[port - start_port]) != 0) {
            perror("Error creating thread");
        }
    }

    // Wait for all threads to complete
    for (int port = start_port; port <= end_port; port++) {
        pthread_join(threads[port - start_port], NULL);

        // Concatenate each result into the final results string
        strcat(final_results, scan_data[port - start_port].result);
        free(scan_data[port - start_port].result); // Free memory allocated for each result
    }

    // Print all the results
    printf("\n--- Scan Results ---\n");
    printf("%s\n", final_results);

    // Prompt user to save the results to a file
    printf("Would you like to save the results to a file? (y/n): ");
    scanf(" %c", &save_results_choice); // Notice the space before %c to consume the newline character

    if (save_results_choice == 'y' || save_results_choice == 'Y') {
        save_results_to_file(hostname, start_port, end_port, timeout, final_results);
    }

    // Free dynamically allocated memory
    free(final_results);

    return 0;
}
