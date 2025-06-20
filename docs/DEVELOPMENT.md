# Harbinger Development Guide

This guide helps developers understand the codebase structure and contribute to Harbinger.

## 🏗️ Architecture Overview

Harbinger follows a modular architecture with clear separation of concerns:

```
harbinger/
├── main.go                    # Entry point
├── cmd/harbinger/            # CLI commands (Cobra)
│   ├── root.go              # Root command setup
│   └── scan.go              # Scan command implementation
├── pkg/                      # Public packages
│   ├── scanner/             # Core scanning logic
│   │   ├── scanner.go       # Main scanner orchestrator
│   │   ├── headers.go       # HTTP header analysis
│   │   ├── ssl.go           # SSL/TLS analysis
│   │   ├── technology.go    # Technology detection (TODO)
│   │   ├── subdomains.go    # Subdomain enumeration (TODO)
│   │   └── vulnerabilities.go # Vulnerability assessment (TODO)
│   ├── tui/                 # Terminal UI components
│   │   └── tui.go           # Bubbletea TUI implementation
│   ├── api/                 # External API integrations (TODO)
│   ├── ai/                  # AI integration (TODO)
│   └── report/              # Report generation (TODO)
├── internal/                 # Private packages
│   ├── models/              # Data structures
│   │   └── scan.go          # Scan result models
│   └── utils/               # Utility functions (TODO)
├── examples/                 # Sample configurations
└── docs/                    # Documentation
```

## 🔧 Core Components

### Scanner Package (`pkg/scanner/`)

The scanner package contains the core vulnerability scanning logic:

- **scanner.go**: Main orchestrator that coordinates all scanning phases
- **headers.go**: HTTP security header analysis
- **ssl.go**: SSL/TLS certificate and configuration analysis

#### Adding New Scan Modules

1. Create a new file in `pkg/scanner/` (e.g., `technology.go`)
2. Implement the scanning function with signature: `func (s *Scanner) analyzeX(ctx context.Context, target string) (*models.XAnalysis, error)`
3. Add the analysis to the main scan flow in `scanner.go`
4. Update the models in `internal/models/scan.go` if needed

### TUI Package (`pkg/tui/`)

The TUI uses the Bubbletea framework for rich terminal interfaces:

- **tui.go**: Main TUI implementation with progress tracking and result display

#### TUI State Management

The TUI follows the Elm architecture pattern:
- **Model**: Holds application state
- **Update**: Handles messages and state transitions  
- **View**: Renders the current state

### Models Package (`internal/models/`)

Contains all data structures used throughout the application:
- **ScanResult**: Complete scan results
- **HeaderAnalysis**: HTTP header analysis results
- **SSLAnalysis**: SSL/TLS analysis results
- **Vulnerability**: Individual vulnerability findings

## 🛠️ Development Workflow

### Prerequisites

- Go 1.21 or later
- Git

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/ajaikumarvs/harbinger.git
cd harbinger

# Install dependencies
go mod download

# Build the application
go build -o harbinger

# Run tests
go test ./...
```

### Running During Development

```bash
# Build and run with live reloading (install air first: go install github.com/cosmtrek/air@latest)
air

# Or manual build and test
go build -o harbinger && ./harbinger scan https://example.com --no-tui
```

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Run `go vet` and `golint` before committing
- Add comments for exported functions and types
- Use meaningful variable and function names

### Testing

- Write unit tests for all public functions
- Use table-driven tests for multiple test cases
- Mock external dependencies for testing
- Aim for >80% test coverage

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...
```

## 📋 TODOs and Future Features

### High Priority
- [ ] Technology stack detection using Wappalyzer
- [ ] Subdomain enumeration via crt.sh API
- [ ] Vulnerability database integration (CVE mapping)
- [ ] PDF/DOCX report generation

### Medium Priority
- [ ] AI-powered analysis integration
- [ ] Wayback Machine integration
- [ ] Security headers API integration
- [ ] Configuration file support improvements

### Low Priority
- [ ] Plugin system for custom scans
- [ ] Database storage for scan history
- [ ] Web dashboard interface
- [ ] Scheduled scanning

## 🤝 Contributing

### Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `go test ./...`
6. Update documentation if needed
7. Commit with descriptive messages
8. Push to your fork: `git push origin feature/amazing-feature`
9. Open a Pull Request

### Commit Message Format

```
type: brief description

Detailed explanation of what this commit does and why.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Code Review Guidelines

- All PRs require at least one review
- Address all review comments
- Keep PRs focused and reasonably sized
- Include tests for new features
- Update documentation as needed

## 🐛 Debugging

### Common Issues

1. **TLS handshake failures**: Check target URL and network connectivity
2. **Context deadline exceeded**: Increase timeout values
3. **Import cycle errors**: Review package dependencies

### Debugging Tools

```bash
# Enable debug logging
export HARBINGER_LOG_LEVEL=debug

# Run with race detection
go run -race main.go scan https://example.com

# Profile memory usage
go run main.go scan https://example.com -cpuprofile=cpu.prof -memprofile=mem.prof
```

## 📚 Resources

- [Go Documentation](https://golang.org/doc/)
- [Cobra CLI Framework](https://cobra.dev/)
- [Bubbletea TUI Framework](https://github.com/charmbracelet/bubbletea)
- [Lipgloss Styling](https://github.com/charmbracelet/lipgloss)
- [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)

## 📞 Getting Help

- Check existing [issues](https://github.com/ajaikumarvs/harbinger/issues)
- Join our [discussions](https://github.com/ajaikumarvs/harbinger/discussions)
- Read the [FAQ](../README.md#faq)

---

Happy coding! 🚀 