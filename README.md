# go-scan

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, concurrent **TCP port scanner** written in **Go**. Built primarily for educational purposes to explore Go's concurrency 
model (goroutines + channels), networking primitives, and clean CLI application design.

**Note**: This is **not** intended for malicious use or unauthorized scanning. Always obtain explicit permission before scanning any network/host you do **not** own.

## Features

- Fast concurrent port scanning using goroutines
- Customizable target host and port range/list
- Clean terminal output (open, closed, filtered)
- Timeout control to avoid hanging on unresponsive hosts
- Modular & well-organized code structure

### Demo

Example output:
```bash
./go-scan -t 45.33.32.156
Starting GoScan 1.0.0 ( https://github.com/CodeZeroSugar/go-scan ) at 2026-02-10 23:34:54

Scan Results for: 45.33.32.156
Port:    22 | State: Open
Port:    80 | State: Open

GoScan done: 1 host(s) scanned in 2.56 seconds
```

#### Installation

##### Prerequisites
go 1.25.5

require (
        github.com/stretchr/testify v1.11.1
        golang.org/x/net v0.49.0
)

require (
        github.com/davecgh/go-spew v1.1.1 // indirect
        github.com/pmezard/go-difflib v1.0.0 // indirect
        golang.org/x/sys v0.40.0 // indirect
        gopkg.in/yaml.v3 v3.0.1 // indirect
)

### Build from source

```bash
# Clone the repo
git clone https://github.com/CodeZeroSugar/go-scan.git
cd go-scan

# Build the binary
go build -o go-scan ./cmd/go-scan

# Or install globally (optional)
go install ./cmd/go-scan
```

Now you can run ./go-scan (or go-scan if installed globally)

###### Usage
A basic but fast TCP port scanner written in Go.

```bash
Usage:
  go-scan [flags]

Flags:
  -f    Display filtered ports. Only open ports are displayed by default.
  -p string
        Input a single port to scan only that port.
        Separate ports with commas (no spaces) to scan those specific ports (22,54,80).
        Provide a range like '1-500' to scan all ports in that range.
        Default is common ports. (default "1-1023")
  -sn
        Toggle for discovery scan only.
        Standard scan uses discovery by default.
        Using this flag will disable port scanning and only ping hosts specified by -t flag.
  -stats
        Display port stats. Cannot be used with other flags.
        Options: top <n>, all

  -t string
        The IP Address you want to scan. Defaults to loopback. (default "127.0.0.1")

  -h, --help
        Show this help message
```

###### Examples
**Scan top 1000 ports on a test host:**
```bash
go-scan -t 45.33.32.156 -p 1-1000
```
**Scan specific common ports:**
```bash
go-scan -t 192.168.1.1 -p 22,80,443,3389
```
**Scan common ports on a full IP range:**
```bash
go-scan -t 192.168.0.0/24
```

####### Why This Project?
This was created as a learning exercise to deeply understand:

- Go's concurrency patterns (goroutines, WaitGroups, channels)
- The net package for TCP connections
- Building production-ready CLI tools with proper flags & output
- Basic network security concepts (ports, states, timeouts)

######## Future Improvements (Roadmap)
- SYN scanning mode (raw sockets)
- Banner grabbing for service/version detection
- More configuration options (timeout, workers, etc)
- Domain name resolution

######### License
This project is licensed under the MIT License — see the LICENSE file for details.

