# 🔍 Harbinger - Web Vulnerability Scanner

Harbinger is a comprehensive, terminal-based web vulnerability scanning tool built in Go. It performs both local and API-based vulnerability scans, presenting results in a beautiful TUI (Terminal User Interface) and generating detailed reports.

## ✨ Features

- **Comprehensive Scanning**: HTTP headers, SSL/TLS analysis, technology detection, subdomain enumeration
- **Beautiful TUI**: Rich terminal interface built with Bubbletea and Lipgloss
- **Multiple Data Sources**: Local analysis + external APIs (crt.sh, securityheaders.com, web.archive.org)
- **AI-Powered Analysis**: Optional AI summaries via Gemini/OpenAI/Claude APIs
- **Export Options**: Generate PDF and DOCX reports
- **Real-time Progress**: Live scanning status with progress bars
- **Cross-platform**: Works on Linux, macOS, and Windows

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ajaikumarvs/harbinger.git
cd harbinger

# Build the application
go build -o harbinger

# Or install directly
go install
```

### Basic Usage

```bash
# Scan a website with TUI
./harbinger scan https://example.com

# Scan without TUI (direct output)
./harbinger scan https://example.com --no-tui

# Scan with output to file
./harbinger scan https://example.com --output report.pdf --format pdf

# Scan with AI analysis
./harbinger scan https://example.com --api-key YOUR_KEY --ai-provider gemini
```

## 📖 Commands

### Scan Command

```bash
harbinger scan [URL] [flags]
```

**Flags:**
- `-t, --target string`: Target URL to scan
- `-o, --output string`: Output file path
- `-f, --format string`: Output format (pdf, docx) (default "pdf")
- `--no-tui`: Disable TUI and run in direct mode
- `--api-key string`: API key for AI analysis
- `--ai-provider string`: AI provider (gemini, openai, claude) (default "gemini")
- `-v, --verbose`: Verbose output

**Global Flags:**
- `--config string`: Config file (default is $HOME/.harbinger.yaml)

## 🏗️ Architecture

```
harbinger/
├── cmd/harbinger/          # CLI commands
├── pkg/
│   ├── scanner/           # Core scanning logic
│   ├── api/              # External API integrations
│   ├── tui/              # Terminal UI components
│   ├── ai/               # AI integration
│   └── report/           # Report generation
├── internal/
│   ├── models/           # Data structures
│   └── utils/            # Utilities
└── docs/                 # Documentation
```

## 🔧 Scanning Modules

### 1. HTTP Header Analysis
- Security headers detection (CSP, HSTS, X-Frame-Options, etc.)
- Missing header identification
- Header value validation
- Security grade calculation

### 2. SSL/TLS Analysis
- Certificate information extraction
- Cipher suite analysis
- Protocol version detection
- Vulnerability identification

### 3. Technology Detection
- Web server identification
- Framework detection
- CMS recognition
- JavaScript library identification

### 4. Subdomain Enumeration
- Certificate transparency logs (crt.sh)
- DNS enumeration
- Subdomain validation

### 5. Archive Analysis
- Wayback Machine integration
- Historical endpoint discovery
- Change tracking

### 6. Vulnerability Assessment
- CVE database integration
- CVSS scoring
- Risk categorization
- Mitigation recommendations

## 🤖 AI Integration

Harbinger supports AI-powered vulnerability analysis through multiple providers:

- **Google Gemini**: Use `--ai-provider gemini`
- **OpenAI GPT**: Use `--ai-provider openai`
- **Anthropic Claude**: Use `--ai-provider claude`

The AI analyzes scan results and provides:
- Executive summary
- Risk prioritization
- Remediation recommendations
- Compliance insights

## 📊 Report Generation

Generate comprehensive reports in multiple formats:

### PDF Reports
- Executive summary
- Detailed findings
- Vulnerability matrix
- Recommendations

### DOCX Reports
- Structured document
- Charts and graphs
- Appendices
- Technical details

## ⚙️ Configuration

Create a configuration file at `~/.harbinger.yaml`:

```yaml
# Default scanning options
scan:
  timeout: 30s
  max_retries: 3
  user_agent: "Harbinger/1.0"

# API configurations
apis:
  security_headers:
    enabled: true
    timeout: 10s
  crt_sh:
    enabled: true
    timeout: 15s

# AI configuration
ai:
  provider: "gemini"
  api_key: "${HARBINGER_AI_KEY}"
  model: "gemini-pro"

# Report settings
reports:
  default_format: "pdf"
  include_raw_data: false
  template: "standard"
```

## 🔐 Security Considerations

- All external API calls are optional
- No data is stored or transmitted without explicit consent
- API keys are handled securely
- Network requests use secure protocols

## 🛠️ Development

### Prerequisites
- Go 1.21+
- Git

### Building from Source

```bash
# Clone and enter directory
git clone https://github.com/ajaikumarvs/harbinger.git
cd harbinger

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o harbinger
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Cobra](https://github.com/spf13/cobra) for CLI framework
- [Bubbletea](https://github.com/charmbracelet/bubbletea) for TUI
- [Lipgloss](https://github.com/charmbracelet/lipgloss) for styling
- [Wappalyzer](https://github.com/projectdiscovery/wappalyzergo) for technology detection

## 📞 Support

- 🐛 [Report bugs](https://github.com/ajaikumarvs/harbinger/issues)
- 💡 [Request features](https://github.com/ajaikumarvs/harbinger/discussions)
- 📖 [Documentation](https://github.com/ajaikumarvs/harbinger/wiki)

---

Made with ❤️ by [ajaikumarvs](https://github.com/ajaikumarvs) 