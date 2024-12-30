"""
Net-Sentinel Setup Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

This module handles package setup and installation configuration.
"""

import os
from setuptools import setup, find_packages

# Read README file
def read_readme():
    with open('README.md', encoding='utf-8') as f:
        return f.read()

# Read requirements file
def read_requirements():
    requirements = []
    with open('requirements.txt', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                requirements.append(line)
    return requirements

setup(
    name="net-sentinel",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive network security assessment tool with AI guidance",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/net-sentinel",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "net-sentinel=net_sentinel.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "net_sentinel": [
            "templates/*.html",
            "templates/*.xml",
            "data/*.json",
        ],
    },
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "mypy>=0.950",
            "pylint>=2.13.0",
            "sphinx>=4.5.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=3.0.0",
            "coverage>=6.3.0",
            "beautifulsoup4>=4.11.0",
        ],
        "docs": [
            "sphinx>=4.5.0",
            "sphinx-rtd-theme>=1.0.0",
            "sphinx-autodoc-typehints>=1.18.0",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourusername/net-sentinel/issues",
        "Documentation": "https://net-sentinel.readthedocs.io/",
        "Source Code": "https://github.com/yourusername/net-sentinel",
    },
    zip_safe=False,
    options={
        'bdist_wheel': {
            'universal': True
        }
    },
    cmdclass={
        'clean': lambda x: None,  # Placeholder for custom clean command
    },
    data_files=[
        ('config', ['config/default_config.json']),
        ('examples', [
            'examples/basic_scan.py',
            'examples/advanced_scan.py',
        ]),
    ],
    platforms=['any'],
)

# Additional setup tasks
if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("src/net_sentinel/templates", exist_ok=True)
    os.makedirs("src/net_sentinel/data", exist_ok=True)
    
    # Create empty files if they don't exist
    if not os.path.exists("README.md"):
        with open("README.md", "w", encoding="utf-8") as f:
            f.write("# Net-Sentinel\n\nA comprehensive network security assessment tool with AI guidance.\n")
    
    if not os.path.exists("requirements.txt"):
        with open("requirements.txt", "w", encoding="utf-8") as f:
            f.write("""
# Core dependencies
scapy>=2.5.0
python-nmap>=0.7.1
requests>=2.28.0
cryptography>=41.0.0
torch>=2.0.0
transformers>=4.30.0
pyyaml>=6.0
jinja2>=3.1.2
lxml>=4.9.0
rich>=13.0.0
python-dotenv>=1.0.0
aiohttp>=3.8.0
asyncio>=3.4.3
            """.strip())
    
    # Create default config if it doesn't exist
    os.makedirs("config", exist_ok=True)
    if not os.path.exists("config/default_config.json"):
        with open("config/default_config.json", "w", encoding="utf-8") as f:
            json.dump({
                "scan_options": {
                    "max_depth": 3,
                    "timeout": 30.0,
                    "concurrent_scans": 10,
                    "user_agent": "Net-Sentinel Security Scanner"
                },
                "ai_options": {
                    "model_type": "local",
                    "temperature": 0.7,
                    "max_tokens": 500
                },
                "reporting": {
                    "default_format": "html",
                    "include_charts": True
                }
            }, f, indent=4)
    
    # Create example files
    os.makedirs("examples", exist_ok=True)
    if not os.path.exists("examples/basic_scan.py"):
        with open("examples/basic_scan.py", "w", encoding="utf-8") as f:
            f.write("""
from net_sentinel import NetworkDiscovery, ScanOptions

async def main():
    scanner = NetworkDiscovery()
    options = ScanOptions(ports="80,443,22")
    results = await scanner.scan_network("192.168.1.0/24", options)
    print(f"Found {len(results)} hosts")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
            """.strip())
    
    if not os.path.exists("examples/advanced_scan.py"):
        with open("examples/advanced_scan.py", "w", encoding="utf-8") as f:
            f.write("""
from net_sentinel import VulnerabilityScanner, ScanConfig, AIGuidance

async def main():
    scanner = VulnerabilityScanner()
    ai = AIGuidance()
    
    config = ScanConfig(max_depth=3)
    results = await scanner.scan_target("192.168.1.0/24", config)
    
    guidance = await ai.analyze_vulnerabilities(results)
    print("AI Recommendations:", guidance.recommendations)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
            """.strip())