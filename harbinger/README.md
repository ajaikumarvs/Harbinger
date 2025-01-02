# Harbinger

A command-line interface (CLI) based security vulnerability assessment tool.

## Project Structure

```
harbinger/
├── src/               # Main application source code
├── modules/           # Scanner modules
├── resources/         # Resource files
├── tests/            # Test suite
├── auth/             # Authentication client
└── setup/            # Build and packaging scripts
```

## Development Setup

1. Install dependencies:
   ```bash
   poetry install
   ```

2. Activate virtual environment:
   ```bash
   poetry shell
   ```

3. Run tests:
   ```bash
   pytest
   ```

## Building

To create executable:
```bash
pyinstaller setup/bundle_spec.py
```
