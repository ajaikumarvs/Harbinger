# 🛡️ Harbinger - CLI Security Scanner

A comprehensive CLI security scanning application built with Go and the Charm Bracelet ecosystem, featuring AI-powered analysis and beautiful terminal interfaces.

## 🚀 Features

### Core Scanning Capabilities
- **Port Scanning** - Service detection and enumeration
- **Technology Detection** - Framework and CMS identification
- **SSL/TLS Analysis** - Certificate validation and security assessment
- **Security Headers** - HTTP security header analysis
- **Directory Discovery** - Common paths and file enumeration
- **DNS Analysis** - DNS records and subdomain discovery

### AI-Powered Analysis
- **Multi-Provider Support** - Google Gemini, OpenAI, Claude, Custom APIs
- **Executive Summaries** - High-level risk assessments
- **Root Cause Analysis** - Deep vulnerability explanations
- **Future Threat Predictions** - Emerging security risks
- **Business Impact Assessment** - Risk to operations
- **Compliance Analysis** - Regulatory gap identification
- **Educational Insights** - Security learning content

### Beautiful TUI Interface
- **Interactive Navigation** - Intuitive menu system
- **Live Progress** - Real-time scan monitoring
- **Tabbed Results** - Organized vulnerability display
- **Color-Coded Scoring** - Visual security assessment
- **Responsive Design** - Adapts to terminal size

## 📋 Prerequisites

- Go 1.21 or later
- Terminal with color support
- Internet connection for external API scans

## 🛠️ Installation

### From Source
```bash
git clone https://github.com/ajaikumarvs/harbinger.git
cd harbinger
go mod tidy
go build -o harbinger
./harbinger
```

### Quick Run
```bash
go run main.go
```

## 🎯 Quick Start

1. **Launch Harbinger**
   ```bash
   ./harbinger
   ```

2. **Configure AI Provider** (Optional but recommended)
   - Navigate to Settings → API Keys
   - Add your preferred AI provider key
   - Test the connection

3. **Start Your First Scan**
   - Select "Scan" from main menu
   - Enter target URL (e.g., https://example.com)
   - Watch live progress
   - Review detailed results

4. **Explore Results**
   - Use Tab/Shift+Tab to navigate sections
   - View vulnerabilities, technologies, and AI analysis
   - Check scan history for previous results

## 🎮 Navigation

| Key | Action |
|-----|--------|
| `↑/↓` or `j/k` | Navigate menus |
| `Enter` | Select/Confirm |
| `Tab/Shift+Tab` | Switch tabs |
| `ESC` | Go back/Cancel |
| `Ctrl+C` | Quit application |

## 🤖 AI Providers

### Supported Providers
- **Google Gemini** 
- **OpenAI** 
- **Anthropic Claude** 
- **Custom APIs** - Bring your own endpoint

### Configuration
1. Go to Settings → API Keys
2. Select provider and enter API key
3. Choose model (optional)
4. Test connection
5. Set as default provider

API keys are encrypted and stored securely on your system.

## 📊 Scan Types

| Type | Duration | Features |
|------|----------|----------|
| **Quick** | 2-5 min | Basic security assessment |
| **Standard** | 5-15 min | Comprehensive analysis |
| **Deep** | 15-30 min | Full scan + AI analysis |

## 🏗️ Architecture

```
harbinger/
├── cmd/              # CLI command definitions
├── internal/
│   ├── config/       # Configuration management
│   ├── scanner/      # Scanning modules
│   ├── ai/          # AI integration
│   ├── tui/         # Terminal UI components
│   ├── export/      # Report generation
│   └── storage/     # Data persistence
├── pkg/
│   └── models/      # Shared data structures
└── main.go          # Application entry point
```

## 🔧 Development Status

### ✅ Phase 1: Core TUI Framework (COMPLETED)
- [x] Main menu navigation
- [x] Scan input interface
- [x] Live progress tracking
- [x] Results display with tabs
- [x] History management
- [x] Settings configuration
- [x] Help documentation

### 🚧 Phase 2: Scanning Engine (IN PROGRESS)
- [ ] Port scanner implementation
- [ ] Technology detection
- [ ] SSL/TLS analyzer
- [ ] Security headers checker
- [ ] DNS analysis tools
- [ ] Directory discovery

### 📋 Phase 3: AI Integration (PLANNED)
- [ ] Multi-provider AI interface
- [ ] Prompt engineering
- [ ] Analysis templates
- [ ] Secure key management
- [ ] Result enrichment

### 📈 Phase 4: Advanced Features (PLANNED)
- [ ] PDF/DOCX export
- [ ] Report templates
- [ ] Data persistence
- [ ] Scan comparisons
- [ ] Performance optimization

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/ajaikumarvs/harbinger.git
cd harbinger
go mod tidy
go run main.go
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Charm Bracelet](https://charm.sh/) - Beautiful TUI components
- [Cobra](https://cobra.dev/) - CLI framework
- [Viper](https://github.com/spf13/viper) - Configuration management

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/ajaikumarvs/harbinger/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/ajaikumarvs/harbinger/discussions)
- 📧 **Email**: ajaikumarvs@example.com

---

**Built with ❤️ by [ajaikumarvs](https://github.com/ajaikumarvs)** 