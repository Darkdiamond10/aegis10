#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

#define EIGHT_MB (8 * 1024 * 1024)

/* ── ISOLATED NETWORK HANDLERS (From c2_client.c) ───────────────────────── */

static inline long raw_socket(int domain, int type, int protocol) {
  long ret;
  __asm__ volatile("mov $41, %%rax\n\t" /* __NR_socket = 41 */
                   "syscall\n\t"
                   : "=a"(ret)
                   : "D"((long)domain), "S"((long)type), "d"((long)protocol)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long raw_connect(int sockfd, const struct sockaddr *addr,
                               socklen_t addrlen) {
  long ret;
  __asm__ volatile("mov $42, %%rax\n\t" /* __NR_connect = 42 */
                   "syscall\n\t"
                   : "=a"(ret)
                   : "D"((long)sockfd), "S"((long)(uintptr_t)addr),
                     "d"((long)addrlen)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long raw_close(int fd) {
  long ret;
  __asm__ volatile("mov $3, %%rax\n\t" /* __NR_close = 3 */
                   "syscall\n\t"
                   : "=a"(ret)
                   : "D"((long)fd)
                   : "rcx", "r11", "memory");
  return ret;
}

static void set_socket_recv_timeout(int sockfd, int seconds) {
  struct timeval tv;
  tv.tv_sec = seconds;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

typedef struct {
  int sockfd;
  bool connected;
} tcp_conn_t;

static int tcp_connect_isolated(tcp_conn_t *conn, const char *ip, uint16_t port) {
    memset(conn, 0, sizeof(*conn));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        return -1;
    }

    long sfd = raw_socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return -1;
    conn->sockfd = (int)sfd;

    long cret = raw_connect(conn->sockfd, (struct sockaddr *)&sa, sizeof(sa));
    if (cret < 0) {
        raw_close(conn->sockfd);
        return -1;
    }

    // 30 second global timeout prevents hangs
    set_socket_recv_timeout(conn->sockfd, 30);

    conn->connected = true;
    return 0;
}

static void tcp_disconnect_isolated(tcp_conn_t *conn) {
    if (!conn) return;
    if (conn->sockfd > 0) {
        raw_close(conn->sockfd);
        conn->sockfd = -1;
    }
    conn->connected = false;
}

static ssize_t tcp_send_isolated(tcp_conn_t *conn, const void *data, size_t len) {
    if (!conn || !conn->connected) return -1;
    return (ssize_t)send(conn->sockfd, data, len, 0);
}

static ssize_t tcp_recv_isolated(tcp_conn_t *conn, void *buf, size_t cap) {
    if (!conn || !conn->connected) return -1;
    return (ssize_t)recv(conn->sockfd, buf, cap, 0);
}

/* ── 8MB PLAINTEXT STRESS TEST ───────────────────────────────────────────── */

void run_8mb_network_isolation_test() {
    printf("[*] Starting 8MB Network Isolation Stress Test (RAW TCP)...\n");

    tcp_conn_t conn;

    printf("    -> Connecting to dummy TCP server at 127.0.0.1:4444...\n");
    int rc = tcp_connect_isolated(&conn, "127.0.0.1", 4444);
    TEST_ASSERT(rc == 0, "Failed to connect to local dummy TCP server");

    // Send HTTP GET request to trigger the 8MB transfer
    const char *req = "GET /8mb_stress HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    ssize_t sent = tcp_send_isolated(&conn, req, strlen(req));
    TEST_ASSERT(sent == (ssize_t)strlen(req), "Failed to send HTTP GET request");

    // Allocate 8MB buffer for receiving
    uint8_t *recv_buf = malloc(EIGHT_MB + 4096); // Pad slightly for headers
    TEST_ASSERT(recv_buf != NULL, "Failed to allocate 8MB receive buffer");

    printf("    -> Receiving 8MB stream...\n");

    size_t total_received = 0;
    ssize_t n;

    // Raw socket core recv loop
    while ((n = tcp_recv_isolated(&conn, recv_buf + total_received, (EIGHT_MB + 4096) - total_received)) > 0) {
        total_received += (size_t)n;
        printf("       ... Received chunk of %zd bytes (Total: %zu bytes)\n", n, total_received);
    }

    // Disconnect
    tcp_disconnect_isolated(&conn);

    printf("    -> Connection closed. Total received: %zu bytes.\n", total_received);

    // Find the end of HTTP headers (\r\n\r\n)
    uint8_t *body = NULL;
    if (total_received >= 4) {
        for (size_t i = 0; i < total_received - 3; i++) {
            if (recv_buf[i] == '\r' && recv_buf[i+1] == '\n' && recv_buf[i+2] == '\r' && recv_buf[i+3] == '\n') {
                body = recv_buf + i + 4;
                break;
            }
        }
    }
    TEST_ASSERT(body != NULL, "Failed to find HTTP headers separator");

    size_t body_len = total_received - (body - recv_buf);
    printf("    -> Payload body length: %zu bytes.\n", body_len);

    // Check if the body length matches 8MB
    if (body_len < EIGHT_MB) {
        fprintf(stderr, "[FAIL] Truncation occurred! Expected %d bytes, got %zu bytes.\n", EIGHT_MB, body_len);
        exit(EXIT_FAILURE);
    }

    // Verify pattern integrity ("AEGIS" repeating)
    printf("    -> Verifying plaintext byte pattern...\n");
    const char *pattern = "AEGIS";
    size_t pat_len = strlen(pattern);

    bool corrupted = false;
    for (size_t i = 0; i < EIGHT_MB; i++) {
        if (body[i] != pattern[i % pat_len]) {
            fprintf(stderr, "[FAIL] Corruption detected at byte %zu! Expected '%c', got '%c' (0x%02X)\n",
                    i, pattern[i % pat_len], body[i], body[i]);
            corrupted = true;
            break;
        }
    }

    TEST_ASSERT(!corrupted, "Data integrity verification failed due to stream corruption.");

    printf("[+] 8MB Network Isolation Test completed flawlessly. No truncation or corruption detected.\n");
    free(recv_buf);
}

int main() {
    printf("========================================================\n");
    printf("  AEGIS NETWORK MODULE DIAGNOSTIC (8MB PLAINTEXT)       \n");
    printf("========================================================\n\n");

    run_8mb_network_isolation_test();

    return 0;
}