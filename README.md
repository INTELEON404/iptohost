<div align="center">
  <img src="https://github.com/INTELEON404/Template/blob/main/iptohost.png" alt="iptohost Logo" />
  
  ---
  [![Version](https://img.shields.io/badge/version-1.2.1-blue.svg)](https://github.com/inteleon404/iptohost)
  [![Go Version](https://img.shields.io/badge/go-%3E%3D1.18-00ADD8.svg)](https://golang.org/)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
  [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/inteleon404/iptohost)
</div>


## 📖 About

**iptohost** is a high-performance reconnaissance tool designed for security professionals, penetration testers, and bug bounty hunters. It rapidly resolves IP addresses to hostnames through SSL/TLS certificate inspection and DNS PTR lookups, providing comprehensive host enumeration for security assessments.

### Why iptohost?

- 🚀 **Blazing Fast**: Multi-threaded architecture with configurable workers
- 🎯 **Dual Discovery**: Combines SSL certificate analysis and DNS PTR lookups
- 🔧 **Highly Configurable**: Custom DNS resolvers, SNI override, flexible output formats
- 📊 **Multiple Output Modes**: Human-readable, JSON, or silent mode for scripting
- 🛡️ **Security Focused**: Built for recon workflows with deduplication and stats tracking
- 🔌 **Pipeline Friendly**: Seamless stdin/stdout integration for tool chaining

---

## ✨ Features

### Core Capabilities
- **SSL/TLS Certificate Enumeration**
  - Extract Subject Alternative Names (SANs)
  - Extract Common Name (CN)
  - Support for custom ports (e.g., `:8443`, `:8080`)
  - SNI override for virtual hosting scenarios

- **DNS PTR Lookups**
  - Reverse DNS resolution
  - Custom DNS resolver support (IP, port, protocol)
  - Configurable timeouts
  - UDP/TCP protocol selection

### Advanced Features
- **Performance Optimization**
  - Configurable worker threads (default: 32)
  - Connection pooling and reuse
  - HTTP/2 support for faster TLS handshakes
  - Rate limiting with configurable delays

- **Output Flexibility**
  - Human-readable format with colored output
  - JSON output for automation
  - Silent mode (hostnames only)
  - Timestamp support (RFC3339)
  - Deduplication options

- **Reliability**
  - Graceful error handling
  - Panic recovery
  - Detailed statistics reporting
  - Verbose logging mode

---

## 🚀 Installation

### Using Go Install (Recommended)
```bash
go install github.com/inteleon404/iptohost@latest
```

### From Source
```bash
git clone https://github.com/inteleon404/iptohost.git
cd iptohost
go build -o iptohost
sudo mv iptohost /usr/local/bin/
```

### Verify Installation
```bash
iptohost -version
```

---

## 📚 Usage

### Basic Examples

**Quick scan from file:**
```bash
iptohost -i targets.txt
```

**Pipeline from stdin:**
```bash
cat ips.txt | iptohost
```

**High-speed scan with 100 workers:**
```bash
iptohost -i targets.txt -t 100
```

### Advanced Examples

**Silent mode for clean output:**
```bash
iptohost -i targets.txt -silent | sort -u
```

**SSL-only enumeration (skip DNS):**
```bash
iptohost -i targets.txt -skip-dns -t 200
```

**DNS-only with custom resolver:**
```bash
iptohost -i targets.txt -skip-ssl -r 8.8.8.8 -p 53
```

**JSON output with statistics:**
```bash
iptohost -i targets.txt -json -stats -dedupe > results.json
```

**Rate-limited scan with delay:**
```bash
iptohost -i targets.txt -delay 100ms -timeout 15
```

**Custom SNI for virtual hosts:**
```bash
iptohost -i targets.txt -sni example.com -insecure
```

**Verbose debugging:**
```bash
iptohost -i targets.txt -v -stats
```

**Complete reconnaissance workflow:**
```bash
cat targets.txt | iptohost -t 100 -dedupe -timestamp -o results.txt -stats
```

---

## 🎛️ Command-Line Options

### Input/Output Options
| Flag | Alias | Description |
|------|-------|-------------|
| `-i` | | Input file containing IPs (default: stdin) |
| `-o` | | Output file for results (default: stdout) |
| `-json` | | Output results in JSON format |
| `-silent` | `-s` | Silent mode - output hostnames only |
| `-timestamp` | | Add RFC3339 timestamps to results |

### Performance Options
| Flag | Alias | Description |
|------|-------|-------------|
| `-t` | `-threads` | Number of concurrent workers (default: 32) |
| `-delay` | | Delay between requests (e.g., `100ms`, `1s`) |
| `-timeout` | | HTTP client timeout in seconds (default: 10) |

### DNS Options
| Flag | Alias | Description |
|------|-------|-------------|
| `-r` | `-resolver` | Custom DNS resolver IP address |
| `-p` | | DNS resolver port (default: 53) |
| `-protocol` | | DNS protocol: `udp` or `tcp` (default: udp) |
| `-dns-timeout` | | DNS lookup timeout in seconds (default: 5) |
| `-skip-dns` | | Skip DNS PTR lookups |

### SSL/TLS Options
| Flag | Description |
|------|-------------|
| `-sni` | Override SNI hostname for SSL connections |
| `-insecure` | Skip TLS certificate verification (default: true) |
| `-skip-ssl` | Skip SSL certificate checks |

### Output Control
| Flag | Alias | Description |
|------|-------|-------------|
| `-dedupe` | | Deduplicate hostnames in output |
| `-stats` | | Show detailed statistics at completion |
| `-v` | `-verbose` | Verbose output with debug information |
| `-banner` | | Show ASCII banner on startup |
| `-version` | | Display version information |

---

## 📤 Output Formats

### Standard Output
```
[SSL-SAN] 143.43.221.133 -> example.com
[SSL-CN] 143.43.221.133 -> example.org
[DNS-PTR] 143.43.221.133 -> host.example.com
[SSL-SAN] 143.43.221.133:8443 -> api.example.com
```

### JSON Output
```json
{
  "type": "SSL-SAN",
  "ip": "143.43.221.133",
  "hostname": "example.com",
  "source": "certificate"
}{
  "type": "SSL-CN",
  "ip": "143.43.221.133",
  "hostname": "example.org",
  "source": "certificate"
}{
  "type": "DNS-PTR",
  "ip": "143.43.221.133",
  "hostname": "host.example.com",
  "source": "dns"
}{
  "type": "SSL-SAN",
  "ip": "143.43.221.133",
  "hostname": "api.example.com",
  "port": "8443",
  "source": "certificate"
}
```

### Silent Mode Output
```
example.com
example.org
host.example.com
api.example.com
```

### Statistics Report
```
╔════════════════════════════════════════════╗
║           Statistics Report                ║
╠════════════════════════════════════════════╣
║ Total IPs processed:    250                ║
║ SSL hostnames found:    487                ║
║ DNS PTR records:        198                ║
║ Unique hostnames:       623                ║
║ Failed checks:          12                 ║
║ Time elapsed:           45.3s              ║
║ Processing rate:        5.52 IPs/s         ║
╚════════════════════════════════════════════╝
```

---

## 🔧 Use Cases

### Bug Bounty Hunting

#### Discover subdomains from IP ranges
```bash
cat ip-ranges.txt | iptohost -silent -dedupe | httprobe
```

### Penetration Testing

#### Enumerate all hosts on discovered IPs
```bash
iptohost -i scope-ips.txt -stats -o discovered-hosts.txt
```

### Asset Discovery

#### Find all hostnames associated with company IPs
```bash
iptohost -i company-ips.txt -json -dedupe > asset-inventory.json
```

### Certificate Transparency Analysis

#### Extract all SANs from certificate monitoring
```bash
cat ct-log-ips.txt | iptohost -skip-dns -t 200 -silent
```

### Reverse DNS Enumeration
#### PTR record enumeration only
```bash
iptohost -i targets.txt -skip-ssl -r 1.1.1.1 -v
```

---

## 🔍 Input Format

iptohost accepts various input formats:

```
# Plain IPs
192.168.1.1
10.0.0.1

# IPs with ports
192.168.1.1:8443
10.0.0.1:9000

# CIDR ranges (each IP should be on its own line)
192.168.1.1
192.168.1.2
192.168.1.3

# Comments (lines starting with #)
# Production servers
192.168.1.100
# Staging servers
192.168.1.200

# HTTP(S) URLs (protocol will be stripped)
https://192.168.1.1
http://10.0.0.1:8080
```

---

## 🛠️ Integration Examples

### With other tools

**Combine with subfinder and httpx:**
```bash
subfinder -d example.com -silent | httpx -silent | iptohost -silent | sort -u
```

**Pipe to nuclei for vulnerability scanning:**
```bash
cat targets.txt | iptohost -silent -dedupe | nuclei -t cves/
```

**Chain with massdns:**
```bash
cat subdomains.txt | massdns -r resolvers.txt -o S -w - | awk '{print $3}' | iptohost
```

**Export to CSV:**
```bash
iptohost -i targets.txt -json | jq -r '[.ip,.hostname,.type] | @csv'
```

---

## ⚙️ Performance Tuning

### For Large-Scale Scans

#### Maximum performance
```bash
iptohost -i massive-list.txt -t 500 -timeout 5 -dns-timeout 3
```

### For Rate-Limited Targets

#### Gentle scanning
```bash
iptohost -i targets.txt -t 10 -delay 500ms -timeout 20
```

### For Accuracy Over Speed

#### Thorough scanning
```bash
iptohost -i targets.txt -t 20 -timeout 30 -dns-timeout 10 -dedupe -stats
```

---

## 📋 Requirements

- **Go**: Version 1.18 or higher
- **Network**: Outbound HTTPS (443) and DNS (53) access
- **Permissions**: No root/admin privileges required

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by the bug bounty and penetration testing communities
- Built for security professionals who need fast, reliable reconnaissance tools
- Special thanks to all contributors and users

---

## 📧 Contact

**INTELEON404** - [@inteleon404](https://github.com/inteleon404)

Project Link: [https://github.com/inteleon404/iptohost](https://github.com/inteleon404/iptohost)

---

<div align="left">
  Made with ❤️ for the security community
  <br/>
  <strong>Happy Hunting! 🎯</strong>
</div>
