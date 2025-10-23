# ipTOhost

**ipTOhost** is a fast and flexible tool for resolving IPs and hosts to their SSL/TLS information and DNS PTR records. It’s designed for penetration testers, bug hunters, and security researchers who need to quickly gather host information.

---

## Features

- Fetch **SSL/TLS certificate info** (SANs and Common Name).
- Perform **PTR (reverse DNS) lookups**.
- Support **custom DNS resolver** (IP, port, UDP/TCP).
- Multi-threaded workers for high-speed scanning.
- Accepts **stdin** or input **file**.
- Optional **SNI override** for TLS handshake.
- Optional **JSON output** for automated parsing.
- Optional **delay** between requests.
- Handles panics and errors gracefully.
- Configurable **TLS verification** (`-insecure`).

---

## Installation

```bash
git clone https://github.com/inteleon404/ipTOhost.git
cd hakip2host
go build -o hakip2host main.go
````

---

## Usage

### From a file:

```bash
./ipTOhost -i targets.txt -t 32
```

### From stdin:

```bash
cat targets.txt | ./hakip2host -t 32
```

### With custom DNS resolver:

```bash
./ipTOhost -i targets.txt -r 8.8.8.8 -p 53 -protocol udp
```

### Override SNI:

```bash
./ipTOhost -i targets.txt -sni example.com
```

### JSON output:

```bash
./ipTOhost -i targets.txt -json
```

### Add delay between requests:

```bash
./ipTOhost -i targets.txt -delay 100ms
```

---

## CLI Flags

| Flag        | Description                                 |
| ----------- | ------------------------------------------- |
| `-t`        | Number of worker threads (default 32)       |
| `-i`        | Input file (default stdin)                  |
| `-r`        | DNS resolver IP (optional)                  |
| `-p`        | DNS resolver port (default 53)              |
| `-protocol` | DNS protocol (udp/tcp, default udp)         |
| `-sni`      | Override SNI host for SSL/TLS               |
| `-insecure` | Skip TLS verification (default true)        |
| `-json`     | Output results as JSON                      |
| `-delay`    | Delay between requests, e.g., 100ms         |
| `-timeout`  | HTTP client timeout in seconds (default 10) |

---

## Example Output

**Human-readable:**

```
[SSL-SAN] 143.43.221.133 example.com
[SSL-CN] 143.43.221.133 example.com
[DNS-PTR] 143.43.221.133 host.example.com
```

**JSON output:**

```json
{"type":"SSL-SAN","ip":"143.43.221.133","data":"example.com"}
{"type":"SSL-CN","ip":"143.43.221.133","data":"example.com"}
{"type":"DNS-PTR","ip":"143.43.221.133","data":"host.example.com"}
```

---

## Requirements

* Go 1.16 or higher
* No external dependencies required

---

## License

MIT License

```

---

If you want, I can also create a **complete GitHub-ready project structure** for `ipTOhost` including:

```

ipTOhost/
├── main.go
├── go.mod
├── README.md
