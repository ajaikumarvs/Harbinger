import os
import sys
import psutil
from llama_cpp import Llama
from termcolor import colored
from contextlib import redirect_stdout, redirect_stderr

# Auto-detect system resources
def get_system_resources():
    """Detect the number of CPU cores and available RAM."""
    cpu_cores = os.cpu_count()  # Total logical cores
    available_memory = psutil.virtual_memory().available // (1024 * 1024)  # RAM in MB
    return cpu_cores, available_memory

# Load the AI model with automatic configuration
def load_model(model_path):
    """Load the Llama model with resource-based configuration."""
    cpu_cores, available_memory = get_system_resources()

    print(f"[INFO] Detected {cpu_cores} CPU cores and {available_memory} MB of available RAM.")
    
    # Configure context size and precision based on RAM
    if available_memory > 8000:  # More than 8GB RAM
        n_ctx = 2048
    elif available_memory > 4000:  # Between 4GB and 8GB RAM
        n_ctx = 1024
    else:  # Less than 4GB RAM
        n_ctx = 512

    try:
        print("[INFO] Initializing the AI model...")
        with open(os.devnull, "w") as devnull:
            with redirect_stdout(devnull), redirect_stderr(devnull):
                llm = Llama(
                    model_path=model_path,
                    n_threads=cpu_cores,
                    n_ctx=n_ctx,
                )
        print("[INFO] Model initialized successfully.")
        return llm
    except Exception as e:
        print(f"[ERROR] Failed to load the AI model: {e}")
        sys.exit(1)

# Function to get AI guidance
def ai_guidance(llm, prompt):
    response = llm(prompt, max_tokens=100)
    return response['choices'][0]['text']

# Function to scan for vulnerabilities
def scan_website(url):
    print(f"Scanning {url} for vulnerabilities...\n")
    # Mock scanning logic
    vulnerabilities = [
        {"name": "SQL Injection", "details": "Detected potential SQL injection vulnerability."},
        {"name": "Cross-Site Scripting (XSS)", "details": "Detected potential XSS vulnerability."},
    ]
    print("Scan complete. Here are the results:\n")
    for vuln in vulnerabilities:
        print(f"- {vuln['name']}: {vuln['details']}")
    return vulnerabilities

# Main workflow
def main():
    MODEL_PATH = "models/whiterabbitneo-q3.gguf"
    if not os.path.exists(MODEL_PATH):
        print("Model file not found! Ensure it's located in the 'models' folder.")
        sys.exit(1)

    llm = load_model(MODEL_PATH)

    print(colored("Welcome to the Web App Vulnerability Scanner!", "blue"))

    # AI guides the user through the process
    intro_prompt = "Guide the user through using a web application vulnerability scanner effectively."
    intro = ai_guidance(llm, intro_prompt)
    print(colored(intro.strip(), "green"))

    # Get the website URL from the user
    url = input("Enter the URL of the website to scan: ")

    # AI gives advice on scanning
    scan_prompt = f"Explain the key steps involved in scanning a website like {url} for vulnerabilities."
    scan_advice = ai_guidance(llm, scan_prompt)
    print(colored(scan_advice.strip(), "green"))

    # Perform the scan
    vulnerabilities = scan_website(url)

    # AI suggests remediation steps
    remediation_prompt = f"Provide remediation steps for the following vulnerabilities: {', '.join([v['name'] for v in vulnerabilities])}."
    remediation_advice = ai_guidance(llm, remediation_prompt)
    print(colored("\nRemediation Guidance:", "green"))
    print(colored(remediation_advice.strip(), "green"))

if __name__ == "__main__":
    main()
