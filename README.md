---

# TCP Port Scanner

A fast, multi-threaded command-line TCP port scanner written in C. This tool efficiently scans a specified range of ports on a target IP address or hostname using non-blocking sockets and `pthreads`.

## Features

*   **Multi-threaded Scanning**: Uses `pthreads` to scan multiple ports in parallel, significantly increasing speed.
*   **Hostname Resolution**: Supports both IP addresses (e.g., `192.168.1.1`) and domain names (e.g., `www.google.com`).
*   **Progress Bar**: Real-time visual progress bar during long scans.
*   **Interactive Interrupt**: Stop the scan at any time by pressing **`q`** or **`ESC`**. The program will exit cleanly and show a summary of results found so far.
*   **Scan Summary**: Displays a clean, sorted list of all open ports at the end of the execution.
*   **Efficient**: Employs non-blocking `connect()` with `select()` for configurable timeouts.

> [!CAUTION]
> This tool is intended for educational purposes only. Port scanning can violate network policies or laws. Use responsibly and only on systems you own or have explicit permission to test.

## Installation

### Prerequisites

*   A C compiler (e.g., GCC) installed.
*   A Unix-like system (Linux, macOS, WSL on Windows) with `pthread` support.

### Build Instructions

Compile the source code using `gcc` with the `-pthread` flag:

```bash
git clone https://github.com/gab-dev-7/port-scanner.git
cd port-scanner
gcc scanner.c -o scanner -pthread
```

## Usage

Execute the scanner with the following syntax:

```bash
./scanner [options] <Target> <Start Port> <End Port>
```

### Arguments

| Argument       | Description                               |
| :------------- | :---------------------------------------- |
| `<Target>`     | Target IP address or Hostname (e.g., `google.com`) |
| `<Start Port>` | Starting TCP port number (1-65535)        |
| `<End Port>`   | Ending TCP port number (1-65535)          |

### Options

| Option | Description | Default |
| :----- | :---------- | :------ |
| `-j <threads>` | Number of concurrent threads to use | 10 |
| `-t <seconds>` | Timeout per port in seconds | 1 |
| `-h`           | Show help message | - |

### Examples

**1. Basic Scan (Localhost)**
Scan ports 1 to 1000 on localhost with default settings:
```bash
./scanner localhost 1 1000
```

**2. Fast Scan (High Performance)**
Scan a web server with 50 threads:
```bash
./scanner -j 50 www.example.com 1 5000
```

**3. Custom Timeout**
Scan with a longer timeout (2 seconds) for slow networks:
```bash
./scanner -t 2 192.168.1.50 1 100
```

## Output Example

```text
--- Starting Port Scan ---
Target: www.example.com (93.184.216.34) | Range: 1 to 1000 | Timeout: 1 sec | Threads: 50
Press 'q' or ESC to stop scanning.
--------------------------
[OPEN] 93.184.216.34:80
[OPEN] 93.184.216.34:443
[========================================] 100%

--------------------------
Summary of Open Ports:
80 443
--------------------------
--- Scan Complete ---
```

## License
MIT
