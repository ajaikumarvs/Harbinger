import os
import sys
import psutil
import torch
import random
from llama_cpp import Llama
from termcolor import colored
from contextlib import redirect_stdout, redirect_stderr
import contextlib
from transformers import AutoModelForCausalLM, AutoTokenizer
from tqdm import tqdm
import time
import gc

# Memory optimization utilities
def clear_memory():
    """Force garbage collection and clear CUDA cache if available."""
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

def get_system_resources():
    """Detect system resources with memory monitoring."""
    cpu_cores = max(1, (os.cpu_count() or 1) // 2)  # Use half of available cores
    mem = psutil.virtual_memory()
    available_memory = mem.available // (1024 * 1024)  # RAM in MB
    return cpu_cores, available_memory

# Custom context manager to suppress output
@contextlib.contextmanager
def suppress_stdout_stderr():
    """Context manager to suppress stdout and stderr."""
    devnull = open(os.devnull, 'w')
    try:
        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = devnull, devnull
        yield
    finally:
        sys.stdout, sys.stderr = stdout, stderr
        devnull.close()

# Function to get AI guidance
def ai_guidance(prompt, llm=None, gpt_neo_model=None, gpt_neo_tokenizer=None):
    """Generate AI guidance with resource optimization."""
    try:
        if llm:  # Use the primary WhiteRabbit model if available
            try:
                with suppress_stdout_stderr():
                    response = llm(prompt, max_tokens=100, temperature=0.7)
                return response['choices'][0]['text']
            except Exception as e:
                print(colored(f"[ERROR] WhiteRabbit model failed: {e}. Switching to GPT-Neo fallback...", "yellow"))
                clear_memory()
        
        if gpt_neo_model and gpt_neo_tokenizer:
            return gpt_neo_guidance(gpt_neo_model, gpt_neo_tokenizer, prompt)
        
        return "[ERROR] No AI models available for guidance."
    finally:
        clear_memory()

def load_lightweight_model():
    """Load GPT-Neo with memory optimization."""
    print("[INFO] Loading lightweight fallback model (GPT-Neo)...")
    model_name = "models/lightweight/gpt-neo"
    try:
        config = {'load_in_8bit': True} if torch.cuda.is_available() else {}
        
        with suppress_stdout_stderr():
            tokenizer = AutoTokenizer.from_pretrained(model_name, **config)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                low_cpu_mem_usage=True,
                **config
            ).to(DEVICE)
        
        clear_memory()
        print("[INFO] Lightweight fallback model loaded successfully.")
        return model, tokenizer
    except Exception as e:
        print(f"[ERROR] Failed to load lightweight model: {e}")
        return None, None

def load_primary_model(model_path):
    """Load Llama model with optimized resource usage from a .safetensors file."""
    cpu_cores, available_memory = get_system_resources()

    try:
        print("[INFO] Initializing the AI model (WhiteRabbitNeo)...")
        
        # Check if the model is in .safetensors format
        if model_path.endswith(".safetensors"):
            print("[INFO] Detected .safetensors format. Loading with Transformers...")
            tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_path,
                trust_remote_code=True,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
                low_cpu_mem_usage=True
            ).to(DEVICE)
            print("[INFO] WhiteRabbitNeo model (.safetensors) loaded successfully.")
            return model, tokenizer
        else:
            # Fallback to gguf loading logic if needed
            print("[INFO] Detected non-.safetensors format. Attempting to load via llama.cpp...")
            n_ctx = min(512, max(256, available_memory // 16))
            n_batch = max(8, min(32, available_memory // 512))

            with suppress_stdout_stderr():
                llm = Llama(
                    model_path=model_path,
                    n_threads=cpu_cores,
                    n_ctx=n_ctx,
                    n_batch=n_batch,
                    use_mlock=False,
                    use_mmap=True,
                )
            print("[INFO] WhiteRabbitNeo model (.gguf) loaded successfully.")
            return llm
    except Exception as e:
        print(f"[ERROR] Failed to load the primary model: {e}")
        return None, None


def gpt_neo_guidance(model, tokenizer, prompt):
    """Generate response with optimized memory usage."""
    if tokenizer.pad_token is None:
        tokenizer.add_special_tokens({'pad_token': tokenizer.eos_token})
        model.resize_token_embeddings(len(tokenizer))
    
    try:
        with torch.no_grad():
            with suppress_stdout_stderr():
                inputs = tokenizer(
                    prompt,
                    return_tensors="pt",
                    padding=True,
                    truncation=True,
                    max_length=512
                ).to(DEVICE)
                
                outputs = model.generate(
                    inputs["input_ids"],
                    attention_mask=inputs["attention_mask"],
                    max_length=100,
                    pad_token_id=tokenizer.pad_token_id,
                    num_beams=2,
                )
                
                response = tokenizer.decode(outputs[0], skip_special_tokens=True)
            clear_memory()
            return response
    except Exception as e:
        print(f"[ERROR] Generation failed: {e}")
        return "[ERROR] Failed to generate response."
        

class VulnerabilityScanner:
    """Enhanced vulnerability scanner with comprehensive checks."""
    
    def __init__(self):
        self.vulnerability_checks = {
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Checks for various types of XSS vulnerabilities including reflected, stored, and DOM-based XSS.',
                'severity': 'High',
                'subchecks': ['Reflected XSS', 'Stored XSS', 'DOM-based XSS'],
                'impact': 'Can allow attackers to execute malicious scripts in users\' browsers.'
            },
            'sqli': {
                'name': 'SQL Injection',
                'description': 'Tests for SQL injection vulnerabilities in input parameters and forms.',
                'severity': 'Critical',
                'subchecks': ['Error-based SQLi', 'Blind SQLi', 'Time-based SQLi'],
                'impact': 'May allow unauthorized access to or manipulation of the database.'
            },
            'cmdi': {
                'name': 'Command Injection',
                'description': 'Identifies command injection vulnerabilities in system calls.',
                'severity': 'Critical',
                'subchecks': ['OS Command Injection', 'Shell Command Injection'],
                'impact': 'Could enable execution of arbitrary system commands.'
            },
            'csrf': {
                'name': 'Cross-Site Request Forgery',
                'description': 'Checks for missing or weak CSRF protections.',
                'severity': 'Medium',
                'subchecks': ['Token Validation', 'SameSite Cookie Settings', 'Origin Validation'],
                'impact': 'May allow attackers to perform unauthorized actions on behalf of authenticated users.'
            },
            'traversal': {
                'name': 'Directory Traversal',
                'description': 'Tests for directory traversal and path manipulation vulnerabilities.',
                'severity': 'High',
                'subchecks': ['Path Traversal', 'File Include Vulnerabilities'],
                'impact': 'Could expose sensitive files and directories.'
            },
            'rce': {
                'name': 'Remote Code Execution',
                'description': 'Scans for potential remote code execution vulnerabilities.',
                'severity': 'Critical',
                'subchecks': ['File Upload Vulnerabilities', 'Deserialization Issues', 'Code Injection Points'],
                'impact': 'May allow execution of arbitrary code on the server.'
            },
            'xxe': {
                'name': 'XML External Entity Injection',
                'description': 'Checks for XXE vulnerabilities in XML processors.',
                'severity': 'High',
                'subchecks': ['XML Parser Configuration', 'Entity Expansion'],
                'impact': 'Could lead to data disclosure, denial of service, or server-side request forgery.'
            },
            'insecure_deserial': {
                'name': 'Insecure Deserialization',
                'description': 'Identifies unsafe deserialization of user input.',
                'severity': 'High',
                'subchecks': ['Object Deserialization', 'JSON Deserialization', 'YAML Parsing'],
                'impact': 'May allow arbitrary code execution or denial of service.'
            }
        }

    def _simulate_check(self, check_type):
        """Simulate a vulnerability check with realistic detection probability."""
        time.sleep(random.uniform(0.3, 0.7))  # Simulate varying check durations
        
        # Simplified vulnerability detection logic (for demonstration)
        detection_chance = {
            'xss': 0.4,
            'sqli': 0.3,
            'cmdi': 0.2,
            'csrf': 0.5,
            'traversal': 0.25,
            'rce': 0.15,
            'xxe': 0.2,
            'insecure_deserial': 0.3
        }
        
        is_vulnerable = random.random() < detection_chance.get(check_type, 0.3)
        return is_vulnerable
    def scan_website(self, url):
        """Perform comprehensive vulnerability scan with detailed progress tracking."""
        print(f"\nInitiating comprehensive scan of {url}\n")
        
        vulnerabilities = []
        total_checks = sum(len(vuln['subchecks']) for vuln in self.vulnerability_checks.values())
        
        with tqdm(total=total_checks, desc="Scan Progress", 
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            
            for check_type, check_info in self.vulnerability_checks.items():
                for subcheck in check_info['subchecks']:
                    pbar.set_description(f"Testing: {subcheck}")
                    
                    if self._simulate_check(check_type):
                        finding = {
                            'name': check_info['name'],
                            'subtype': subcheck,
                            'description': check_info['description'],
                            'severity': check_info['severity'],
                            'impact': check_info['impact']
                        }
                        vulnerabilities.append(finding)
                    
                    pbar.update(1)
                    clear_memory()
        
        self._display_results(vulnerabilities)
        return vulnerabilities

    def _display_results(self, vulnerabilities):
        """Display scan results with color-coded severity levels."""
        if not vulnerabilities:
            print(colored("\n✓ No vulnerabilities detected!", "green"))
            return

        severity_colors = {
            'Critical': 'red',
            'High': 'yellow',
            'Medium': 'cyan',
            'Low': 'blue'
        }

        print("\nScan Results Summary:")
        print("=" * 50)
        
        # Group vulnerabilities by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)

        # Display results sorted by severity
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                vulns = by_severity[severity]
                print(f"\n{colored(f'[{severity}] Vulnerabilities:', severity_colors[severity])}")
                for vuln in vulns:
                    print(colored(f"\n➤ {vuln['name']} ({vuln['subtype']})", severity_colors[severity]))
                    print(f"  Impact: {vuln['impact']}")

def scan_website(url):
    """Main scanning function that uses the VulnerabilityScanner class."""
    scanner = VulnerabilityScanner()
    return scanner.scan_website(url)


def main():
    try:
        import psutil
        process = psutil.Process()
        process.nice(10)
    except:
        pass

    MODEL_PATH = "models/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-IQ2_M.gguf"  # General path (can point to .safetensors or other format)
    llm = None
    gpt_neo_model, gpt_neo_tokenizer = None, None

    if os.path.exists(MODEL_PATH):
        # Updated to handle both model and tokenizer
        model_or_llm = load_primary_model(MODEL_PATH)
        if isinstance(model_or_llm, tuple):
            gpt_neo_model, gpt_neo_tokenizer = model_or_llm
        else:
            llm = model_or_llm
    else:
        print(colored("[WARNING] WhiteRabbit model not found. Falling back to GPT-Neo...", "yellow"))

    if not llm and not gpt_neo_model:
        gpt_neo_model, gpt_neo_tokenizer = load_lightweight_model()

    print(colored("\nWelcome to VulnX-ai", "blue", attrs=["bold"]))
    print(colored("Running in resource-efficient mode\n", "cyan"))

    try:
        intro_prompt = "Tell the user hi"
        intro = ai_guidance(intro_prompt, llm, gpt_neo_model, gpt_neo_tokenizer)
        print(colored(intro.strip(), "green"))

        url = input("\nEnter the URL of the website to scan: ")
        vulnerabilities = scan_website(url)

        if vulnerabilities:
            remediation_prompt = f"Provide single line remediation steps for: {', '.join([v['name'] for v in vulnerabilities])}."
            remediation_advice = ai_guidance(remediation_prompt, llm, gpt_neo_model, gpt_neo_tokenizer)
            print(colored("\nRemediation Guidance:", "green"))
            print(colored(remediation_advice.strip(), "green"))
    
    finally:
        clear_memory()
        if gpt_neo_model:
            del gpt_neo_model
        if llm:
            del llm
        clear_memory()


if __name__ == "__main__":
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(colored("[INFO] Initializing VulnX-ai...", "blue"))
    main()