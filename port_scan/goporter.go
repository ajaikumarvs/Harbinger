package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Dictionary of common ports and their associated service names
var servicePorts = map[int]string{
	20:  "FTP Data Transfer",
	21:  "FTP Control",
	22:  "SSH",
	23:  "Telnet",
	25:  "SMTP",
	53:  "DNS",
	80:  "HTTP",
	110: "POP3",
	143: "IMAP",
	443: "HTTPS",
	3389: "RDP (Remote Desktop)",
	8080: "HTTP (Alternate)",
	3306: "MySQL",
	5432: "PostgreSQL",
	6379: "Redis",
	27017: "MongoDB",
}

// Function to display ASCII art from a file
func displayAsciiArt() {
	file, err := os.Open("art.txt")
	if err != nil {
		fmt.Println("Error opening ASCII art file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading ASCII art file:", err)
	}
}

// Function to scan a single port and identify its service
func scanPort(host string, port int, openPorts *[]string, timeout time.Duration, wg *sync.WaitGroup, mu *sync.Mutex) {
	defer wg.Done()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	serviceName := servicePorts[port]
	if serviceName == "" {
		serviceName = "Unknown Service"
	}

	mu.Lock()
	*openPorts = append(*openPorts, fmt.Sprintf("Port %d is open on %s (%s)", port, host, serviceName))
	mu.Unlock()
}

// Function to scan multiple ports concurrently using goroutines
func scanPorts(host string, startPort, endPort int, timeout time.Duration, maxThreads int) []string {
	var openPorts []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Channel for limiting concurrent goroutines
	sem := make(chan struct{}, maxThreads)

	for port := startPort; port <= endPort; port++ {
		sem <- struct{}{} // Acquire a token
		wg.Add(1)

		go func(port int) {
			defer func() { <-sem }() // Release the token
			scanPort(host, port, &openPorts, timeout, &wg, &mu)
		}(port)
	}

	wg.Wait()
	return openPorts
}

// Function to print the consolidated open ports
func printConsolidatedResults(openPorts []string) {
	if len(openPorts) > 0 {
		fmt.Println("\nConsolidated Results of Open Ports:")
		fmt.Println(strings.Repeat("-", 40))
		for _, result := range openPorts {
			fmt.Println(result)
		}
		fmt.Println(strings.Repeat("-", 40))
	} else {
		fmt.Println("No open ports found.")
	}
}

// Function to save the results to a file
func saveResultsToFile(targetHost string, startPort, endPort int, timeout time.Duration, openPorts []string, filename string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	file.WriteString(fmt.Sprintf("\n--- Scan Results for %s ---\n", targetHost))
	file.WriteString(fmt.Sprintf("Ports Scanned: %d-%d\n", startPort, endPort))
	file.WriteString(fmt.Sprintf("Timeout: %.2fs\n", timeout.Seconds()))
	if len(openPorts) > 0 {
		file.WriteString("Open Ports:\n")
		for _, result := range openPorts {
			file.WriteString(result + "\n")
		}
	} else {
		file.WriteString("No open ports found.\n")
	}
	file.WriteString(strings.Repeat("-", 40) + "\n")

	fmt.Printf("Results saved to %s\n", filename)
}

// Main menu for the program
func displayMenu() string {
	fmt.Println("\n--- Port Scanner Menu ---")
	fmt.Println("1. Start a new scan")
	fmt.Println("2. Redo the last scan")
	fmt.Println("3. Exit")
	var choice string
	fmt.Print("Choose an option: ")
	fmt.Scan(&choice)
	return choice
}

// Function to execute a port scan
func runPortScan() (string, int, int, time.Duration, []string) {
	var targetHost string
	var startPort, endPort, maxThreads int
	var timeout float64

	fmt.Print("Enter the target host (IP or domain): ")
	fmt.Scan(&targetHost)

	fmt.Print("Enter the start port: ")
	fmt.Scan(&startPort)

	fmt.Print("Enter the end port: ")
	fmt.Scan(&endPort)

	fmt.Print("Enter timeout in seconds (default 1 second): ")
	fmt.Scan(&timeout)
	if timeout == 0 {
		timeout = 1.0
	}

	fmt.Print("Enter max number of threads for parallel scanning (e.g. 50): ")
	fmt.Scan(&maxThreads)
	if maxThreads == 0 {
		maxThreads = 50
	}

	portsToScan := endPort - startPort + 1
	fmt.Printf("\nScanning %s from port %d to %d...\n", targetHost, startPort, endPort)

	startTime := time.Now()

	openPorts := scanPorts(targetHost, startPort, endPort, time.Duration(timeout)*time.Second, maxThreads)

	printConsolidatedResults(openPorts)

	elapsedTime := time.Since(startTime)
	fmt.Printf("\nScan completed in %.2f seconds.\n", elapsedTime.Seconds())

	var saveResults string
	fmt.Print("Would you like to save the results to a file? (y/n): ")
	fmt.Scan(&saveResults)
	if strings.ToLower(saveResults) == "y" {
		saveResultsToFile(targetHost, startPort, endPort, time.Duration(timeout)*time.Second, openPorts, "scan_results.txt")
	}

	return targetHost, startPort, endPort, time.Duration(timeout) * time.Second, openPorts
}

func main() {
	var lastScan struct {
		targetHost string
		startPort  int
		endPort    int
		timeout    time.Duration
		openPorts  []string
	}

	// Display ASCII art when the program starts
	displayAsciiArt()

	for {
		choice := displayMenu()

		switch choice {
		case "1":
			lastScan.targetHost, lastScan.startPort, lastScan.endPort, lastScan.timeout, lastScan.openPorts = runPortScan()
		case "2":
			if lastScan.targetHost != "" {
				fmt.Println("\nRedoing the last scan...\n")
				lastScan.openPorts = scanPorts(lastScan.targetHost, lastScan.startPort, lastScan.endPort, lastScan.timeout, 50)
				printConsolidatedResults(lastScan.openPorts)
				var saveResults string
				fmt.Print("Would you like to save the results to a file? (y/n): ")
				fmt.Scan(&saveResults)
				if strings.ToLower(saveResults) == "y" {
					saveResultsToFile(lastScan.targetHost, lastScan.startPort, lastScan.endPort, lastScan.timeout, lastScan.openPorts, "scan_results.txt")
				}
			} else {
				fmt.Println("No previous scan to redo.")
			}
		case "3":
			fmt.Println("Exiting program...")
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}
