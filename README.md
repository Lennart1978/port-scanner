---

# TCP Port Scanner

A lightweight, command-line TCP port scanner written in C. This tool efficiently scans a specified range of ports on a target IP address using non-blocking sockets and the `select()` system call for configurable timeouts.

## Features

*   **Efficient Scanning**: Employs non-blocking `connect()` with `select()` for a configurable timeout per port (default: 1 second), preventing hangs on unresponsive hosts.
*   **Clean Output**: Reports only open ports (`[OPEN]`) and timeouts (`[TIMEOUT]`). Closed ports (immediate refusals) are silently skipped for concise output.
*   **IPv4 Support**: Handles standard IPv4 addresses.
*   **Robust Error Handling**: Gracefully manages invalid IPs, ports, and socket errors.
*   **Lightweight**: Single-file implementation with minimal dependencies (standard Unix networking libraries).

> [!CAUTION]
> This tool is intended for educational purposes only. Port scanning can violate network policies or laws. Use responsibly and only on systems you own or have explicit permission to test.

## Installation

### Prerequisites

*   A C compiler (e.g., GCC) installed.
*   A Unix-like system (Linux, macOS, WSL on Windows) with standard networking libraries (`arpa/inet.h`, `sys/socket.h`, `sys/select.h`, etc.).
*   No external dependencies are required.

### Build Instructions

Clone the repository and compile the source code:

```bash
git clone https://github.com/gab-dev-7/port-scanner.git
cd port-scanner
gcc -o scanner scanner.c
```

This command produces an executable named `scanner`.

## Usage

Execute the scanner with three required arguments: target IP address, starting port number, and ending port number.

```bash
./scanner <IP_ADDRESS> <START_PORT> <END_PORT>
```

### Example

Scan ports 1 through 100 on the local host (`127.0.0.1`):

```bash
./scanner 127.0.0.1 1 100
```

**Sample Output:**

```
--- Starting Port Scan ---
Target: 127.0.0.1 | Range: 1 to 100 | Timeout: 1 second(s)
--------------------------
[TIMEOUT] 127.0.0.1:22
[OPEN] 127.0.0.1:80
--- Scan Complete ---
```

*   `[OPEN]`: The port accepted a connection, indicating a service might be listening.
*   `[TIMEOUT]`: No response was received within the timeout period (suggesting a firewall, a slow host, or a filtered port).
*   **Closed Ports**: Ports that immediately return a "connection refused" are not displayed to keep the output focused.

### Arguments

| Argument       | Description                               | Constraints                     |
| :------------- | :---------------------------------------- | :------------------------------ |
| `<IP_ADDRESS>` | The target IPv4 address (e.g., `192.168.1.1`) | Must be a valid IPv4 address.   |
| `<START_PORT>` | The starting TCP port number.             | Must be between 1 and 65535.    |
| `<END_PORT>`   | The ending TCP port number.               | Must be between 1 and 65535, and greater than or equal to `<START_PORT>`. |

**Timeout Configuration**: The default timeout is 1 second per port. To modify this, adjust the `TIMEOUT` variable defined in the `main()` function within the source code.

## How It Works

The scanner performs a **TCP connect scan** across the specified port range:

1.  **Socket Initialization**: Creates a new TCP socket (`AF_INET`, `SOCK_STREAM`).
2.  **Non-Blocking Mode**: Sets the socket to non-blocking mode using `fcntl()` with `O_NONBLOCK`. This allows the `connect()` call to return immediately, even if the connection is still in progress.
3.  **Connection Attempt**: Initiates an asynchronous connection attempt with `connect()`. If the call returns immediately and `errno` is set to `EINPROGRESS`, the connection attempt is ongoing.
4.  **Timeout Enforcement**: Uses `select()` on the socket's write file descriptor set, paired with a `struct timeval` specifying the timeout duration. This waits for the socket to become writable, which indicates the connection attempt has completed (either successfully or with an error).
5.  **Status Determination**: After `select()` returns, the scanner queries the socket's `SO_ERROR` option using `getsockopt()`:
    *   If the retrieved error value is `0`, the connection was successful, and the port is reported as **OPEN**.
    *   If the retrieved error value is non-zero (e.g., `ECONNREFUSED`), the connection failed, and the port is considered **CLOSED** or resulted in another error (which might be reported as a timeout depending on the specific error).
6.  **Cleanup**: The socket is closed after each scan attempt.

This methodology is effective against firewalls and unresponsive hosts and does not require root privileges, as it uses standard `connect()` calls.

## Limitations

*   **TCP Only**: Currently, only TCP ports are scanned. UDP scanning is not supported.
*   **IPv4 Only**: Does not support IPv6 addresses.
*   **Sequential Scanning**: Ports are scanned one by one. For large port ranges (e.g., 1-65535), scanning can take a significant amount of time. Parallelization is not implemented.
*   **No Root Required / Detectability**: Uses a full connect scan, which might be logged by intrusion detection systems (IDS) or firewalls.
*   **No Service Detection**: Only determines if a port is open or closed. It does not attempt to identify the specific service running on an open port (unlike tools like `nmap`).
*   **Platform Specificity**: The implementation relies on Unix socket APIs and will require modifications (e.g., using Winsock) to run on Windows.

## Potential Improvements

*   Add support for UDP port scanning.
*   Implement parallel scanning using threads or `poll()` for faster execution on large ranges.
*   Add options for JSON or CSV output formats for easier integration with scripts or other tools.
*   Add support for IPv6 addresses.
*   Introduce a command-line flag to allow users to configure the timeout value dynamically.
*   Implement basic service banner grabbing on open ports.
*   Add support for scanning multiple hosts or CIDR ranges.
