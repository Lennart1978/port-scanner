#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h> // Necessary for select()
#include <sys/socket.h>
#include <unistd.h>

// Prototypes
int scan_port(const char *ip, int port, int timeout_sec);

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: %s <IP Address> <Start Port> <End Port>\n", argv[0]);
    printf("Example: %s 192.168.1.1 1 100\n", argv[0]);
    return 1;
  }

  const char *target_ip = argv[1];
  int start_port = atoi(argv[2]);
  int end_port = atoi(argv[3]);
  const int TIMEOUT = 1; // 1 second timeout for each port

  if (start_port <= 0 || end_port > 65535 || start_port > end_port) {
    printf("Error: Invalid port range [%d - %d].\n", start_port, end_port);
    return 1;
  }

  printf("--- Starting Port Scan ---\n");
  printf("Target: %s | Range: %d to %d | Timeout: %d second(s)\n", target_ip,
         start_port, end_port, TIMEOUT);
  printf("--------------------------\n");

  // Loop through the requested range
  for (int port = start_port; port <= end_port; port++) {
    int result = scan_port(target_ip, port, TIMEOUT);

    // Print results only for non-closed ports (OPEN or TIMEOUT)
    if (result == 0) {
      printf("[OPEN] %s:%d\n", target_ip, port);
    } else if (result == 1) {
      // Note: TIMEOUT often means a firewall is present or the host is slow
      printf("[TIMEOUT] %s:%d\n", target_ip, port);
    }
    // Result -1 (CLOSED) is ignored for cleaner output
  }

  printf("--- Scan Complete ---\n");
  return 0;
}

// Function to perform the single port scan with a timeout
int scan_port(const char *ip, int port, int timeout_sec) {
  int sock;
  struct sockaddr_in server_addr;

  // 1. Create Socket
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    // perror("Socket creation failed"); // Suppress noise on errors
    return -2;
  }

  // 2. Set to Non-Blocking Mode
  if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
    // perror("Failed to set non-blocking mode");
    close(sock);
    return -2;
  }

  // 3. Define Target Address
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
    // fprintf(stderr, "Invalid IP address: %s\n", ip); // Suppress noise on
    // errors
    close(sock);
    return -2;
  }

  // 4. Initiate Non-Blocking Connect
  connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

  // Check errno for EINPROGRESS (connection is underway)
  if (errno != EINPROGRESS) {
    // This means it failed instantly (e.g., connection refused)
    close(sock);
    return -1; // CLOSED
  }

  // 5. Use select() for Timeout
  fd_set writefds;
  FD_ZERO(&writefds);
  FD_SET(sock, &writefds);

  struct timeval timeout;
  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = 0;

  // select() will block until the socket is ready OR the timeout expires.
  int select_result = select(sock + 1, NULL, &writefds, NULL, &timeout);

  if (select_result <= 0) {
    // 0: Timeout expired, < 0: Error occurred
    close(sock);
    return 1; // TIMEOUT
  }

  // 6. Final Status Check (If select() returned > 0)
  int so_error;
  socklen_t len = sizeof(so_error);

  // Get the socket options to check for pending errors left by the connect()
  // call
  if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
    close(sock);
    return -2;
  }

  close(sock);

  // If so_error is 0, the connection succeeded (OPEN)
  return so_error == 0 ? 0 : -1; // OPEN (0) or CLOSED (-1)
}
