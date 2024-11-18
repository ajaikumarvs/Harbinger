import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

# Dictionary of common ports and their associated service names
SERVICE_PORTS = {
    20: 'FTP Data Transfer',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3389: 'RDP (Remote Desktop)',
    8080: 'HTTP (Alternate)',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB',
}

# Function to scan a single port and identify its service
def scan_port(host, port, open_ports, timeout, lock):
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)  # Set timeout

    try:
        # Try to connect to the port
        result = sock.connect_ex((host, port))  # connect_ex returns 0 if successful
        if result == 0:
            # Determine the service type from the port
            service_name = SERVICE_PORTS.get(port, 'Unknown Service')
            with lock:  # Ensure thread-safe printing
                print(f"Port {port} is open on {host} ({service_name})")
            open_ports.append((port, service_name))  # Add open port to the list
        else:
            with lock:  # Ensure thread-safe printing for closed ports
                print(f"Port {port} is closed on {host}")
    except socket.error as e:
        with lock:  # Handle errors and print them thread-safely
            print(f"Error scanning port {port} on {host}: {e}")
    finally:
        sock.close()

# Function to scan multiple ports concurrently using ThreadPoolExecutor
def scan_ports(host, ports, timeout, max_threads):
    open_ports = []  # List to store open ports and their services
    lock = threading.Lock()  # Lock for thread-safe printing
    
    # Using ThreadPoolExecutor to manage the threads
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, port, open_ports, timeout, lock): port for port in ports}
        
        # Wait for all futures to complete and handle results as they complete
        for future in as_completed(futures):
            future.result()
    
    return open_ports

# Function to print the consolidated open ports
def print_consolidated_results(open_ports):
    if open_ports:
        print("\nConsolidated Results of Open Ports:")
        print("-" * 40)
        for port, service in sorted(open_ports):
            print(f"Port {port}: {service}")
        print("-" * 40)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    # Input host and ports to scan
    target_host = input("Enter the target host (IP or domain): ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))
    timeout = float(input("Enter timeout in seconds (default 1 second): ") or 1)
    max_threads = int(input("Enter max number of threads for parallel scanning (e.g. 50): ") or 50)

    # Generate list of ports to scan
    ports_to_scan = range(start_port, end_port + 1)

    print(f"\nScanning {target_host} from port {start_port} to {end_port}...")

    # Start the timer to measure efficiency
    start_time = time.time()

    # Scan the ports and get the list of open ports
    open_ports = scan_ports(target_host, ports_to_scan, timeout, max_threads)

    # Print the consolidated results
    print_consolidated_results(open_ports)

    # Output the time it took to scan
    elapsed_time = time.time() - start_time
    print(f"\nScan completed in {elapsed_time:.2f} seconds.")
