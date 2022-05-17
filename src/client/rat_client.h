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

void compress_buffer(struct compression* compress);
void decompress_buffer(struct compression* decompress);
void upload_file(struct compression *compress, mbedtls_ssl_context ssl);
void download_file(struct compression *compress, mbedtls_ssl_context ssl);
