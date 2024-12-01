import os
import requests
import hashlib

# Replace with your VirusTotal API key
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"

def calculate_file_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def scan_file_virustotal(file_path):
    """Scan a file using the VirusTotal API."""
    file_hash = calculate_file_hash(file_path)
    if not file_hash:
        print("Failed to calculate file hash.")
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    print(f"Scanning file: {file_path}")
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        file_info = data.get("data", {}).get("attributes", {})
        scan_results = file_info.get("last_analysis_results", {})
        print(f"Results for {file_path}:\n")
        for engine, result in scan_results.items():
            print(f"Engine: {engine}")
            print(f"Result: {result.get('result', 'Clean')}")
            print(f"Category: {result.get('category', 'N/A')}\n")
    elif response.status_code == 404:
        print("File not found in VirusTotal database. Consider uploading it for a new scan.")
    else:
        print(f"Failed to scan file. HTTP {response.status_code}: {response.text}")

def scan_exe_files_in_directory(directory):
    """Scan all .exe files in a given directory."""
    if not os.path.isdir(directory):
        print(f"Invalid directory: {directory}")
        return

    exe_files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith(".exe")]
    if not exe_files:
        print("No .exe files found in the directory.")
        return

    for exe_file in exe_files:
        scan_file_virustotal(exe_file)

if __name__ == "__main__":
    target_directory = input("Enter the directory containing .exe files: ")
    scan_exe_files_in_directory(target_directory)
