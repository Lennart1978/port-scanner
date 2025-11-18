Simple C Port Scanner

This project is a command-line utility implemented in C that scans a range of TCP ports on a specified IP address. It uses non-blocking sockets and the select() function to implement a connection timeout, preventing the application from hanging on unresponsive hosts.

📁 Project Structure

File

Description

scanner.c

The core application logic, which accepts an IP address and a port range, and attempts to establish a TCP connection to each port within that range.

⚙️ Compilation

This project requires standard networking libraries available on Linux/Unix-like environments. Compile using GCC and link with the necessary libraries (often implicit):

gcc -o scanner scanner.c

🚀 How to Run

The program requires three command-line arguments: the target IP address, the starting port, and the ending port.

Usage:

./scanner <IP Address> <Start Port> <End Port>

Example (Scanning the first 100 ports on localhost):

./scanner 127.0.0.1 1 100

Output

The scanner will output the status of each port it checks:

[OPEN]: A TCP connection was successfully established.

[TIMEOUT]: The connection attempt timed out, often indicating a filtered port (e.g., by a firewall). Ports that are definitively closed (Connection Refused) are not displayed for cleaner output.

📝 Key Concepts Demonstrated

Non-Blocking Sockets: Using fcntl to set the socket to non-blocking mode (O_NONBLOCK).

Connection Timeout: Utilizing the select() system call to wait for a connection attempt to complete within a specified time limit.

Error Handling: Checking getsockopt for the SO_ERROR after select() returns to determine the final connection status (open or closed).
