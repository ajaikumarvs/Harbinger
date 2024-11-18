import socket
from concurrent.futures import ThreadPoolExecutor

# Function to scan a single port
def scan_port(host, port):
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set timeout to 1 second

    # Try to connect to the port
    result = sock.connect_ex((host, port))  # connect_ex returns 0 if successful
    if result == 0:
        print(f"Port {port} is open on {host}")
    else:
        print(f"Port {port} is closed on {host}")
    sock.close()

# Function to scan multiple ports concurrently
def scan_ports(host, ports):
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit tasks to the executor for each port
        for port in ports:
            executor.submit(scan_port, host, port)

if __name__ == "__main__":
    # Input host and ports to scan
    target_host = input("Enter the target host (IP or domain): ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))

    # Generate list of ports to scan
    ports_to_scan = range(start_port, end_port + 1)

    print(f"Scanning {target_host} from port {start_port} to {end_port}...")

    # Scan the ports
    scan_ports(target_host, ports_to_scan)
