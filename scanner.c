#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <termios.h>

// Enums for clarity
typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_TIMEOUT,
    PORT_ERROR
} ScanResult;

// Shared configuration and state
typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int start_port;
    int end_port;
    int timeout_sec;
    int thread_count;
} ScanConfig;

typedef struct {
    int current_port;
    int *open_ports;
    int open_count;
    pthread_mutex_t lock;
} ScanState;

ScanConfig config;
ScanState state;
volatile int stop_scan = 0;
volatile int threads_finished = 0;
struct termios orig_termios;
pthread_mutex_t print_lock;

// Prototypes
ScanResult scan_port(const char *ip, int port, int timeout_sec);
void *worker_thread(void *arg);
void *input_monitor_thread(void *arg);
void *progress_thread(void *arg);
void print_usage(const char *prog_name);
int resolve_hostname(const char *hostname, char *ip_str);
int compare_ints(const void *a, const void *b);
void disable_raw_mode();
void enable_raw_mode();

int main(int argc, char *argv[]) {
    // Disable buffering for instant output
    setvbuf(stdout, NULL, _IONBF, 0);

    // Default values
    config.timeout_sec = 1;
    config.thread_count = 10;
    int opt;

    while ((opt = getopt(argc, argv, "t:j:h")) != -1) {
        switch (opt) {
            case 't':
                config.timeout_sec = atoi(optarg);
                if (config.timeout_sec <= 0) {
                    fprintf(stderr, "Invalid timeout value.\n");
                    return 1;
                }
                break;
            case 'j':
                config.thread_count = atoi(optarg);
                if (config.thread_count <= 0 || config.thread_count > 1000) {
                    fprintf(stderr, "Invalid thread count (1-1000).\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind + 3 != argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *target_input = argv[optind];
    char *endptr;
    long start = strtol(argv[optind + 1], &endptr, 10);
    if (*endptr != '\0') { fprintf(stderr, "Invalid start port.\n"); return 1; }
    
    long end = strtol(argv[optind + 2], &endptr, 10);
    if (*endptr != '\0') { fprintf(stderr, "Invalid end port.\n"); return 1; }

    config.start_port = (int)start;
    config.end_port = (int)end;

    // Resolve Hostname/IP
    if (resolve_hostname(target_input, config.target_ip) != 0) {
        fprintf(stderr, "Could not resolve hostname: %s\n", target_input);
        return 1;
    }

    if (config.start_port <= 0 || config.end_port > 65535 || config.start_port > config.end_port) {
        printf("Error: Invalid port range [%d - %d].\n", config.start_port, config.end_port);
        return 1;
    }

    // Enable raw mode for input monitoring
    enable_raw_mode();

    printf("--- Starting Port Scan ---\n");
    printf("Target: %s (%s) | Range: %d to %d | Timeout: %d sec | Threads: %d\n", 
           target_input, config.target_ip, config.start_port, config.end_port, config.timeout_sec, config.thread_count);
    printf("Press 'q' or ESC to stop scanning.\n");
    printf("--------------------------\n");

    // Initialize state
    state.current_port = config.start_port;
    state.open_count = 0;
    // Allocate max possible size
    state.open_ports = malloc(sizeof(int) * (config.end_port - config.start_port + 1));
    if (!state.open_ports) {
        perror("Failed to allocate memory for results");
        disable_raw_mode();
        return 1;
    }

    if (pthread_mutex_init(&state.lock, NULL) != 0) {
        perror("Mutex init failed");
        free(state.open_ports);
        disable_raw_mode();
        return 1;
    }
    if (pthread_mutex_init(&print_lock, NULL) != 0) {
        perror("Print mutex init failed");
        free(state.open_ports);
        pthread_mutex_destroy(&state.lock);
        disable_raw_mode();
        return 1;
    }

    // Start Input Monitor Thread
    pthread_t input_thread;
    if (pthread_create(&input_thread, NULL, input_monitor_thread, NULL) != 0) {
        perror("Failed to create input thread");
        free(state.open_ports);
        pthread_mutex_destroy(&state.lock);
        pthread_mutex_destroy(&print_lock);
        disable_raw_mode();
        return 1;
    }

    // Start Progress Bar Thread
    pthread_t prog_thread;
    if (pthread_create(&prog_thread, NULL, progress_thread, NULL) != 0) {
        perror("Failed to create progress thread"); 
        // Proceed without it?
    }

    // Create worker threads
    pthread_t *threads = malloc(sizeof(pthread_t) * config.thread_count);
    if (!threads) {
        perror("Failed to allocate memory for threads");
        stop_scan = 1;
    } else {
        for (int i = 0; i < config.thread_count; i++) {
            if (pthread_create(&threads[i], NULL, worker_thread, NULL) != 0) {
                perror("Thread creation failed");
                stop_scan = 1; 
            }
        }

        // Join worker threads
        for (int i = 0; i < config.thread_count; i++) {
            if (threads[i]) pthread_join(threads[i], NULL); 
        }
        free(threads);
    }
    
    threads_finished = 1;
    pthread_join(prog_thread, NULL);

    pthread_cancel(input_thread);
    pthread_join(input_thread, NULL); 

    disable_raw_mode(); // Restore terminal settings

    // Summary
    printf("\n--------------------------\n");
    printf("Summary of Open Ports:\n");
    
    qsort(state.open_ports, state.open_count, sizeof(int), compare_ints);

    if (state.open_count == 0) {
        printf("No open ports found.\n");
    } else {
        for (int i = 0; i < state.open_count; i++) {
            printf("%d ", state.open_ports[i]);
        }
        printf("\n");
    }
    printf("--------------------------\n");
    if (stop_scan) {
         printf("--- Scan Aborted by User ---\n");
    } else {
         printf("--- Scan Complete ---\n");
    }

    free(state.open_ports);
    pthread_mutex_destroy(&state.lock);
    pthread_mutex_destroy(&print_lock);

    return 0;
}

void disable_raw_mode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode);

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON); // Disable echo and canonical mode
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void *progress_thread(void *arg) {
    int total_ports = config.end_port - config.start_port + 1;
    int bar_width = 40;

    while (!stop_scan && !threads_finished) {
        int done = state.current_port - config.start_port;
        if (done > total_ports) done = total_ports;
        
        float progress = (float)done / total_ports;
        int pos = bar_width * progress;

        pthread_mutex_lock(&print_lock);
        printf("\r[");
        for (int i = 0; i < bar_width; ++i) {
            if (i < pos) printf("=");
            else if (i == pos) printf(">");
            else printf(" ");
        }
        printf("] %3d%%", (int)(progress * 100));
        fflush(stdout);
        pthread_mutex_unlock(&print_lock);

        usleep(100000); // 100ms
    }
    // Final update
    pthread_mutex_lock(&print_lock);
    printf("\r[");
    for (int i = 0; i < bar_width; ++i) printf("=");
    printf("] 100%%\r\n"); // Newline after finished
    pthread_mutex_unlock(&print_lock);
    
    return NULL;
}

void *input_monitor_thread(void *arg) {
    while (!stop_scan && !threads_finished) {
        int c = getchar();
        if (c == 'q' || c == 'Q' || c == 27) { // 27 is ESC
            stop_scan = 1;
            break;
        }
        if (c == EOF) break;
    }
    return NULL;
}

int resolve_hostname(const char *hostname, char *ip_str) {
    struct addrinfo hints, *res;
    void *ptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Force IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    ptr = &(ipv4->sin_addr);
    inet_ntop(AF_INET, ptr, ip_str, INET_ADDRSTRLEN);

    freeaddrinfo(res);
    return 0;
}

void *worker_thread(void *arg) {
    while (!stop_scan) {
        int port;
        
        pthread_mutex_lock(&state.lock);
        if (state.current_port > config.end_port) {
            pthread_mutex_unlock(&state.lock);
            break;
        }
        port = state.current_port++;
        pthread_mutex_unlock(&state.lock);

        if (stop_scan) break; 

        ScanResult result = scan_port(config.target_ip, port, config.timeout_sec);

        if (result == PORT_OPEN) {
            pthread_mutex_lock(&print_lock);
            // Clear current line (progress line)
            printf("\r\033[K");
            printf("[OPEN] %s:%d\r\n", config.target_ip, port);
            pthread_mutex_unlock(&print_lock);
            
            // Store for summary
            pthread_mutex_lock(&state.lock);
            state.open_ports[state.open_count++] = port;
            pthread_mutex_unlock(&state.lock);
        }
    }
    return NULL;
}

ScanResult scan_port(const char *ip, int port, int timeout_sec) {
    int sock;
    struct sockaddr_in server_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) return PORT_ERROR;
    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) { close(sock); return PORT_ERROR; }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr); 

    int res = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    if (res < 0) {
        if (errno == EINPROGRESS) {
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            struct timeval timeout;
            timeout.tv_sec = timeout_sec;
            timeout.tv_usec = 0;
            
            int select_res = select(sock + 1, NULL, &writefds, NULL, &timeout);
            if (select_res <= 0) { 
                close(sock); 
                return (select_res == 0) ? PORT_TIMEOUT : PORT_ERROR; 
            }
            
            int so_error;
            socklen_t len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                close(sock); return PORT_ERROR;
            }
            if (so_error != 0) {
                close(sock); return PORT_CLOSED;
            }
        } else {
            close(sock); return PORT_CLOSED;
        }
    }
    
    close(sock);
    return PORT_OPEN;
}

int compare_ints(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options] <IP or Hostname> <Start Port> <End Port>\n", prog_name);
    printf("Options:\n");
    printf("  -t <seconds>  Set timeout per port (default: 1)\n");
    printf("  -j <threads>  Set number of threads (default: 10)\n");
    printf("Example: %s -t 2 -j 50 google.com 80 443\n", prog_name);
}
