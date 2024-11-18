import asyncio
import aiohttp
import socket
from aiohttp import ClientSession

# Function to perform an asynchronous ping sweep
async def ping_host(session: ClientSession, ip: str):
    """
    Asynchronously ping a host to check if it is online using an ICMP echo request.
    """
    url = f'http://{ip}'
    try:
        async with session.get(url, timeout=1) as response:
            if response.status == 200:
                print(f"[LIVE] Host {ip} is online")
                return ip
    except:
        return None

# Function to perform asynchronous port scanning on live hosts
async def grab_banner(ip: str, port: int):
    """
    Attempt to grab a banner from a service on a specific port to identify the OS.
    """
    try:
        # Use asyncio.wait_for() to enforce a timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=2
        )
        
        # Try sending a simple request and read the banner
        writer.write(b'HEAD / HTTP/1.0\r\n\r\n')  # Try sending a HEAD request
        await writer.drain()
        
        banner = await reader.read(1024)
        banner = banner.decode('utf-8', errors='ignore')
        
        # Close the connection after reading
        writer.close()
        await writer.wait_closed()

        if not banner:
            return None
        
        return banner

    except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError) as e:
        # Catch connection errors and return None when failed
        print(f"Error connecting to {ip}:{port} - {e}")
        return None

# Asynchronous function to scan for live hosts in a range
async def scan_network(ip_range: str):
    live_hosts = []
    tasks = []
    async with aiohttp.ClientSession() as session:
        for i in range(1, 255):
            ip = f"{ip_range}.{i}"
            tasks.append(ping_host(session, ip))
        live_hosts = await asyncio.gather(*tasks)
    return [ip for ip in live_hosts if ip]

# Function to perform the full scan of the network and identify OS
async def identify_os(ip: str):
    banners = {}
    common_ports = [80, 443, 22, 21]  # Example ports: HTTP, HTTPS, SSH, FTP
    
    print(f"Identifying OS for {ip}...")
    tasks = [grab_banner(ip, port) for port in common_ports]
    results = await asyncio.gather(*tasks)
    
    for port, banner in zip(common_ports, results):
        if banner:
            print(f"[BANNER] {ip}:{port} - {banner}")
            banners[port] = banner

    # Simple checks based on banners (this can be expanded)
    if any("Windows" in banner for banner in banners.values()):
        return "Windows"
    elif any("Linux" in banner for banner in banners.values()):
        return "Linux"
    elif any("Apache" in banner for banner in banners.values()):
        return "Linux (Apache Web Server)"
    elif any("nginx" in banner for banner in banners.values()):
        return "Linux (Nginx Web Server)"
    return "Unknown OS"

# Main entry point to perform the scan and identify OS
async def scan_and_identify_os(network_range: str):
    live_hosts = await scan_network(network_range)
    os_info = {}
    tasks = [identify_os(ip) for ip in live_hosts]
    os_results = await asyncio.gather(*tasks)

    for ip, os in zip(live_hosts, os_results):
        os_info[ip] = os
        print(f"[RESULT] IP: {ip}, OS: {os}")
    return os_info

if __name__ == "__main__":
    # Define the network range (e.g., 192.168.1.0/24)
    network_range = "192.168.1"  # Last octet will range from 1 to 254

    # Perform the scan and identify the OS of each device
    asyncio.run(scan_and_identify_os(network_range))
