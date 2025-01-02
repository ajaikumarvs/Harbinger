#!/bin/bash

# Create main project directory
mkdir -p harbinger

# Create source directory structure
mkdir -p harbinger/src/{cli,core,utils}
touch harbinger/src/main.py
touch harbinger/src/cli/__init__.py
touch harbinger/src/core/__init__.py
touch harbinger/src/utils/__init__.py
touch harbinger/src/cli/command_handler.py
touch harbinger/src/cli/interface.py
touch harbinger/src/core/config.py
touch harbinger/src/core/module_loader.py
touch harbinger/src/utils/logger.py

# Create modules structure
mkdir -p harbinger/modules/{common,malware_scanner,network_scanner,web_scanner}
touch harbinger/modules/common/{__init__.py,base_scanner.py}
mkdir -p harbinger/modules/malware_scanner/models
touch harbinger/modules/malware_scanner/{__init__.py,scanner.py}
touch harbinger/modules/network_scanner/{__init__.py,scanner.py}
touch harbinger/modules/web_scanner/{__init__.py,scanner.py}

# Create resources structure
mkdir -p harbinger/resources/{models,config}

# Create tests structure
mkdir -p harbinger/tests/{unit/test_modules,integration}

# Create auth directory
mkdir -p harbinger/auth
touch harbinger/auth/{__init__.py,client.py}

# Create setup directory
mkdir -p harbinger/setup
touch harbinger/setup/bundle_spec.py

# Create project configuration file
touch harbinger/pyproject.toml

# Initialize git repository
cd harbinger
git init

# Create .gitignore
cat > .gitignore << EOL
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Project specific
resources/models/*.safetensors
EOL

# Initialize basic pyproject.toml
cat > pyproject.toml << EOL
[tool.poetry]
name = "harbinger"
version = "0.1.0"
description = "CLI-based security vulnerability assessment tool"
authors = ["Your Name <your.email@example.com>"]

[tool.poetry.dependencies]
python = "^3.8"
click = "^8.1.0"
typer = "^0.9.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
black = "^23.0.0"
isort = "^5.0.0"
flake8 = "^6.0.0"
mypy = "^1.0.0"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
EOL

# Initialize basic README
cat > README.md << EOL
# Harbinger

A command-line interface (CLI) based security vulnerability assessment tool.

## Project Structure

\`\`\`
harbinger/
├── src/               # Main application source code
├── modules/           # Scanner modules
├── resources/         # Resource files
├── tests/            # Test suite
├── auth/             # Authentication client
└── setup/            # Build and packaging scripts
\`\`\`

## Development Setup

1. Install dependencies:
   \`\`\`bash
   poetry install
   \`\`\`

2. Activate virtual environment:
   \`\`\`bash
   poetry shell
   \`\`\`

3. Run tests:
   \`\`\`bash
   pytest
   \`\`\`

## Building

To create executable:
\`\`\`bash
pyinstaller setup/bundle_spec.py
\`\`\`
EOL

# Make directories accessible
chmod -R 755 .

echo "Project structure created successfully!"
echo "Next steps:"
echo "1. cd harbinger"
echo "2. Initialize poetry: poetry init"
echo "3. Install dependencies: poetry install"
echo "4. Create virtual environment: poetry shell"
