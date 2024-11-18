#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <time.h>

#define TIMEOUT 1 // Timeout in seconds for socket connection
#define MAX_THREADS 50

// Mapping of common port numbers to service names
typedef struct {
    int port;
    const char *service_name;
} ServicePort;

ServicePort service_ports[] = {
    {20, "FTP Data Transfer"},
    {21, "FTP Control"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {3389, "RDP (Remote Desktop)"},
    {8080, "HTTP (Alternate)"},
    {3306, "MySQL"},
    {5432, "PostgreSQL"},
    {6379, "Redis"},
    {27017, "MongoDB"},
};

// Function to get the service name from the port number
const char *get_service_name(int port) {
    for (int i = 0; i < sizeof(service_ports) / sizeof(ServicePort); i++) {
        if (service_ports[i].port == port) {
            return service_ports[i].service_name;
        }
    }
    return "Unknown Service";
}

// Function to scan a single port
void *scan_port(void *arg) {
    int port = *((int *)arg);
    struct sockaddr_in server_addr;
    int sock;
    struct timeval tv;
    int result;
    char *hostname = "localhost"; // Modify as needed for your target

    // Set up the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(hostname); // Use IP address

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    // Set the socket timeout
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
        perror("Failed to set socket timeout");
        close(sock);
        return NULL;
    }

    // Attempt to connect
    result = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (result == 0) {
        printf("Port %d is open (%s)\n", port, get_service_name(port));
    } else {
        printf("Port %d is closed\n", port);
    }

    close(sock);
    return NULL;
}

// Function to scan multiple ports concurrently
void scan_ports(int start_port, int end_port, int max_threads) {
    pthread_t threads[max_threads];
    int port_range = end_port - start_port + 1;
    int thread_count = 0;

    for (int port = start_port; port <= end_port; port++) {
        // Start a new thread for each port scan
        pthread_create(&threads[thread_count], NULL, scan_port, (void *)&port);
        thread_count++;

        // Wait for threads to complete when the limit is reached
        if (thread_count == max_threads) {
            for (int i = 0; i < thread_count; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0; // Reset for new batch of threads
        }
    }

    // Join any remaining threads
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
}

// Function to save scan results to a file
void save_results(const char *hostname, int start_port, int end_port) {
    FILE *file = fopen("scan_results.txt", "a");
    if (!file) {
        perror("Failed to open results file");
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[26];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(file, "\n--- Scan Results for %s (%s) ---\n", hostname, time_buffer);
    fprintf(file, "Ports Scanned: %d-%d\n", start_port, end_port);

    fclose(file);
    printf("Results saved to scan_results.txt\n");
}

int main() {
    int start_port, end_port;
    int max_threads = MAX_THREADS;

    // Input the target host and port range
    char hostname[256];
    printf("Enter the target host (IP address or domain): ");
    scanf("%s", hostname);

    printf("Enter the start port: ");
    scanf("%d", &start_port);

    printf("Enter the end port: ");
    scanf("%d", &end_port);

    // Start the scan
    printf("\nScanning %s from port %d to %d...\n", hostname, start_port, end_port);

    // Measure the start time
    clock_t start_time = clock();

    // Scan the ports
    scan_ports(start_port, end_port, max_threads);

    // Output the time it took to scan
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("\nScan completed in %.2f seconds.\n", elapsed_time);

    // Ask user to save the results
    char save_results;
    printf("Would you like to save the results to a file? (y/n): ");
    scanf(" %c", &save_results);
    if (save_results == 'y' || save_results == 'Y') {
        save_results(hostname, start_port, end_port);
    }

    return 0;
}
