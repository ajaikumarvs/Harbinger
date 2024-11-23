import os
import sys
from llama_cpp import Llama
from termcolor import colored
from contextlib import redirect_stdout, redirect_stderr

# Load the AI model
MODEL_PATH = "model/whiterabbitneo.gguf"
if not os.path.exists(MODEL_PATH):
    print("Model file not found! Ensure it's located in the 'models' folder.")
    sys.exit(1)

print("[INFO] Initializing the AI model...")

# Suppress debug output during model loading
try:
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull), redirect_stderr(devnull):
            llm = Llama(model_path=MODEL_PATH)
    print("[INFO] Model initialized successfully.")
except Exception as e:
    print("[ERROR] Failed to load the AI model.")
    sys.exit(1)

# Function to get AI guidance
def ai_guidance(prompt):
    response = llm(prompt)
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
    print(colored("Welcome to the Web App Vulnerability Scanner!", "blue"))

    # AI guides the user through the process
    intro_prompt = "Guide the user through using a web application vulnerability scanner effectively."
    intro = ai_guidance(intro_prompt)
    print(colored(intro.strip(), "green"))

    # Get the website URL from the user
    url = input("Enter the URL of the website to scan: ")

    # AI gives advice on scanning
    scan_prompt = f"Explain the key steps involved in scanning a website like {url} for vulnerabilities."
    scan_advice = ai_guidance(scan_prompt)
    print(colored(scan_advice.strip(), "green"))

    # Perform the scan
    vulnerabilities = scan_website(url)

    # AI suggests remediation steps
    remediation_prompt = f"Provide remediation steps for the following vulnerabilities: {', '.join([v['name'] for v in vulnerabilities])}."
    remediation_advice = ai_guidance(remediation_prompt)
    print(colored("\nRemediation Guidance:", "green"))
    print(colored(remediation_advice.strip(), "green"))

if __name__ == "__main__":
    main()
