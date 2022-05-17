#include <poll.h>

#include "mbedtls/net.h"

#define PORT "5000"
#define BACKLOG 10
#define BUFFER_SIZE 16384

struct compression {
    unsigned char *orig_buffer;
    unsigned char *transformed_buffer;
    int orig_size;
    int transformed_size;
};

struct ssl_conn {
    mbedtls_net_context conn_fd;
    mbedtls_ssl_context ssl_fd;
    struct ssl_conn *next;
};

void add_client(struct ssl_conn **head, struct ssl_conn **client_conn);
void decompress_buffer(struct compression *compress);
void compress_buffer(struct compression *compress);
//static void callback_to_ip(struct compression *compress);
void upload_file(struct compression *decompress, struct ssl_conn *client_conn);
void download_file(struct compression *compress, struct ssl_conn *client_conn);
void client_disconnect(struct ssl_conn **head, struct pollfd *fds, int fd, int *nfds);
