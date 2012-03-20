#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "testappAscii.h"

#define TMP_TEMPLATE "/tmp/test_file.XXXXXXX"

void parse_tokens(char **tokens, char * response);
uint64_t get_cas_value(char *a);
uint64_t get_cas_value_from_gets(char *a);
enum test_return { TEST_SKIP, TEST_PASS, TEST_FAIL };

typedef uint16_t in_port_t;
static pid_t server_pid;
static in_port_t port;
static int sock;

static pid_t start_server(in_port_t *port_out, bool daemon, int timeout) {
    char environment[80];
    snprintf(environment, sizeof(environment),
             "MEMCACHED_PORT_FILENAME=/tmp/ports.%lu", (long)getpid());
    char *filename= environment + strlen("MEMCACHED_PORT_FILENAME=");
    char pid_file[80];
    snprintf(pid_file, sizeof(pid_file), "/tmp/pid.%lu", (long)getpid());

    remove(filename);
    remove(pid_file);

    char engine[1024];
    assert(getcwd(engine, sizeof(engine)));
    strcat(engine, "/.libs/default_engine.so");
    assert(strlen(engine) < sizeof(engine));

    char blackhole[1024];
    assert(getcwd(blackhole, sizeof(blackhole)));
    strcat(blackhole, "/.libs/blackhole_logger.so");

    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0) {
        /* Child */
        char *argv[20];
        int arg = 0;
        char tmo[24];
        snprintf(tmo, sizeof(tmo), "%u", timeout);

        putenv(environment);

/*
        if (!daemon) {
            argv[arg++] = "./timedrun";
            argv[arg++] = tmo;
        }
*/
        argv[arg++] = "/usr/local/bin/memcached";
       // argv[arg++] = "-E";
       // argv[arg++] = engine;
       // argv[arg++] = "-X";
       // argv[arg++] = blackhole;
        argv[arg++] = "-p";
        argv[arg++] = "-1";
        argv[arg++] = "-U";
        argv[arg++] = "0";
        /* Handle rpmbuild and the like doing this as root */
        if (getuid() == 0) {
            argv[arg++] = "-u";
            argv[arg++] = "root";
        }
        if (daemon) {
            argv[arg++] = "-d";
            argv[arg++] = "-P";
            argv[arg++] = pid_file;
        }
#ifdef MESSAGE_DEBUG
         argv[arg++] = "-vvv";
#endif
        argv[arg++] = NULL;
        assert(execv(argv[0], argv) != -1);
    }

    /* Yeah just let us "busy-wait" for the file to be created ;-) */
    while (access(filename, F_OK) == -1) {
        usleep(10);
    }

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open the file containing port numbers: %s\n",
                strerror(errno));
        assert(false);
    }

    *port_out = (in_port_t)-1;
    char buffer[80];
    while ((fgets(buffer, sizeof(buffer), fp)) != NULL) {
        if (strncmp(buffer, "TCP INET: ", 10) == 0) {
            int32_t val;
            val = strtol(buffer + 10, NULL, 10);
            *port_out = (in_port_t)val;
        }
    }
    fclose(fp);
    assert(remove(filename) == 0);

    if (daemon) {
        /* loop and wait for the pid file.. There is a potential race
         * condition that the server just created the file but isn't
         * finished writing the content, but I'll take the chance....
         */
        while (access(pid_file, F_OK) == -1) {
            usleep(10);
        }

        fp = fopen(pid_file, "r");
        if (fp == NULL) {
            fprintf(stderr, "Failed to open pid file: %s\n",
                    strerror(errno));
            assert(false);
        }
        assert(fgets(buffer, sizeof(buffer), fp) != NULL);
        fclose(fp);

        int32_t val;
        val = strtol(buffer, NULL, 10);
        pid = (pid_t)val;
    }

    return pid;
}


static struct addrinfo *lookuphost(const char *hostname, in_port_t port)
{
    struct addrinfo *ai = 0;
    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                              .ai_protocol = IPPROTO_TCP,
                              .ai_socktype = SOCK_STREAM };
    char service[NI_MAXSERV];
    int error;

    (void)snprintf(service, NI_MAXSERV, "%d", port);
    if ((error = getaddrinfo(hostname, service, &hints, &ai)) != 0) {
       if (error != EAI_SYSTEM) {
          fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
       } else {
          perror("getaddrinfo()");
       }
    }

    return ai;
}

static int connect_server(const char *hostname, in_port_t port, bool nonblock)
{
    struct addrinfo *ai = lookuphost(hostname, port);
    int sock = -1;
    if (ai != NULL) {
       if ((sock = socket(ai->ai_family, ai->ai_socktype,
                          ai->ai_protocol)) != -1) {
          if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
             fprintf(stderr, "Failed to connect socket: %s\n",
                     strerror(errno));
             close(sock);
             sock = -1;
          } else if (nonblock) {
              int flags = fcntl(sock, F_GETFL, 0);
              if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                  fprintf(stderr, "Failed to enable nonblocking mode: %s\n",
                          strerror(errno));
                  close(sock);
                  sock = -1;
              }
          }
       } else {
          fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
       }

       freeaddrinfo(ai);
    }
    return sock;
}

static void send_ascii_command(const char *buf) {
    off_t offset = 0;
    const char* ptr = buf;
    size_t len = strlen(buf);
    printf("sending command <%s>",buf);

    do {
        ssize_t nw = send(sock, ptr + offset, len - offset, 0);
        if (nw == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to write: %s\n", strerror(errno));
                abort();
            }
        } else {
            offset += nw;
        }
    } while (offset < len);
}

/*
 * This is a dead slow single byte read, but it should only read out
 * _one_ response and I don't have an input buffer... The current
 * implementation only supports single-line responses, so if you want to use
 * it for get commands you need to implement that first ;-)
 */
static size_t read_ascii_response(char *buffer, size_t size) {
    off_t offset = 0;
    bool need_more = true;
    do {
        ssize_t nr = recv(sock, buffer + offset, 1, 0);
        if (nr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to read: %s\n", strerror(errno));
                abort();
            }
        } else if (nr == 0) {
                need_more = false;
                buffer[offset] = '\0';
                fprintf(stderr, "Connection closed by peer\n");
	}
	else {
            if (buffer[offset] == '\n') {
                need_more = false;
                buffer[offset + 1] = '\0';
            }
            offset += nr;
            assert(offset + 1 < size);
        }
    } while (need_more);

    printf("i have in buffer %s \n", buffer);
    return offset;
}

static enum test_return start_memcached_server(void) {
    server_pid = start_server(&port, false, 600);
    sock = connect_server("127.0.0.1", port, false);

    return TEST_PASS;
}

static enum test_return stop_memcached_server(void) {
    close(sock);
    assert(kill(server_pid, SIGTERM) == 0);
    return TEST_PASS;
}

static off_t storage_command(char *buf,
                             size_t bufsz,
                             char *cmd,
                             const char* key,
                             size_t keylen,
                             const void* dta,
                             int dtalen,
                             uint32_t flags,
                             uint32_t exp,
                             uint64_t cas) {
    int j = 0, len;
    if (!dta) {
        return 0;
    }
    if (!cas) {
        len = snprintf (buf, bufsz, "%s %s %d %d %d\r\n", cmd, key, flags, exp, dtalen); 
    }
    else {
        len = snprintf (buf, bufsz, "%s %s %d %d %d %llu returncas\r\n", cmd, key, flags, exp, dtalen, (unsigned long long)cas);
    }

    j = dtalen < bufsz-len-3 ? dtalen : bufsz-len-3;  
    memcpy(buf+len, dta, j);
    strncpy(buf+len+j, "\r\n", 3);
    return len+j+3;
}

static off_t raw_command(char* buf,
                         size_t bufsz,
                         char *cmd,
                         const void* key,
                         size_t keylen,
                         const void* dta,
                         size_t dtalen) {
    memcpy(buf, cmd, strlen(cmd)); 
    
    if (key != NULL) {
        memcpy(buf+strlen(cmd), " ",1);
        memcpy(buf+strlen(cmd)+1, key, keylen);
        keylen++;
    }
		
     if (dta != NULL) {
        memcpy(buf+strlen(cmd)+keylen, " ",1);
        memcpy(buf+strlen(cmd)+keylen+1, dta, dtalen);
	dtalen++;
    }
	   
    memcpy(buf+strlen(cmd)+keylen+dtalen, "\r\n",3);
    return 3+keylen + dtalen;
}


void parse_tokens(char **tokens, char * response) {
    int tok =0;
    do {
        tokens[tok++] = response;
        while (*response != '\0' && 
		*response != ' ') {
            response++;
        }
    }while (*response++);
}


static int get_code_for_cmd(char *cmd)
{
	if (!strcmp(cmd, PROTOCOL_CMD_ADD))
		return PROTOCOL_CMD_ADD_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_REPLACE))
		return PROTOCOL_CMD_REPLACE_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_SET))
		return PROTOCOL_CMD_SET_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_APPEND))
		return PROTOCOL_CMD_APPEND_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_PREPEND))
		return PROTOCOL_CMD_PREPEND_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_DELETE))
		return PROTOCOL_CMD_DELETE_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_DECREMENT))
		return PROTOCOL_CMD_DECREMENT_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_INCREMENT))
		return PROTOCOL_CMD_INCREMENT_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_STAT))
		return PROTOCOL_CMD_STAT_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_VERSION))
		return PROTOCOL_CMD_VERSION_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_GET))
		return PROTOCOL_CMD_GET_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_CAS))
		return PROTOCOL_CMD_CAS_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_QUIT))
		return PROTOCOL_CMD_QUIT_CODE;
	else if ( !strcmp(cmd, PROTOCOL_CMD_FLUSH))
		return PROTOCOL_CMD_FLUSH_CODE;
	else
		return -1;
}

static void validate_response(char *cmd, char *response, uint8_t expected)
{
        char *tokens[8];
        parse_tokens(tokens ,response);
        printf("response is %s token 0 is %s", response,tokens[0]);
        switch (get_code_for_cmd(cmd)) {
        case PROTOCOL_CMD_ADD_CODE:
        case PROTOCOL_CMD_REPLACE_CODE:
        case PROTOCOL_CMD_SET_CODE:
             switch (expected) {
             case PROTOCOL_RESPONSE_KEY_EEXISTS:
             case PROTOCOL_RESPONSE_KEY_ENOSTORED:
                assert(!strncmp(tokens[0], "NOT_STORED", strlen("NOT_STORED")));
                break;
    
             case PROTOCOL_RESPONSE_KEY_ENOENT:
                assert(!strncmp(tokens[0], "NOT_FOUND", strlen("NOT_FOUND")));
                break;
    
             default:
                assert(!strncmp(tokens[0], "STORED", 6));
                break;   
             } 
             break;

        case PROTOCOL_CMD_APPEND_CODE:
        case PROTOCOL_CMD_PREPEND_CODE:
             if (expected == PROTOCOL_RESPONSE_NOT_STORED) {
                assert(!strncmp(tokens[0], "NOT_STORED", strlen("NOT_STORED")));
                break;
             }
             assert(!strncmp(tokens[0], "STORED", strlen("STORED")));
             break;

        case PROTOCOL_CMD_DELETE_CODE:
             if (expected == PROTOCOL_RESPONSE_KEY_ENOENT) {
                assert(!strncmp(tokens[0], "NOT_FOUND", sizeof("NOT_FOUND")-1));
                break;
             }
             assert(!strncmp(tokens[0], "DELETED", sizeof("DELETED")-1));
             break;

        case PROTOCOL_CMD_DECREMENT_CODE:
        case PROTOCOL_CMD_INCREMENT_CODE:
             assert(!strstr(response, "ERROR"));   
             break;

        case PROTOCOL_CMD_STAT_CODE:
             assert(!strstr(response, "ERROR"));   
             break;

        case PROTOCOL_CMD_VERSION_CODE:
             assert(!strncmp(tokens[0], "VERSION", sizeof("VERSION")-1));
             break;

        case PROTOCOL_CMD_GET_CODE:
             if (expected == PROTOCOL_RESPONSE_KEY_ENOENT) {
                assert(!strncmp(tokens[0], "END", sizeof("END")-1));
                break;
             }
             assert(!strncmp(response, "VALUE", sizeof("VALUE") -1));   
             assert(!strstr(response, "ERROR"));   
             break;

        case PROTOCOL_CMD_QUIT_CODE:
             assert(*response == '\0');
             break; 

        case PROTOCOL_CMD_FLUSH_CODE:
             assert(!strncmp(response, "OK", sizeof("OK") -1));   
             break; 

        case PROTOCOL_CMD_CAS_CODE:
             if (expected == PROTOCOL_RESPONSE_KEY_ENOENT) {
                assert(!strncmp(tokens[0], "NOT_FOUND", sizeof("NOT_FOUND")-1));
                break;
             }
             assert(!strncmp(tokens[0], "STORED", sizeof("STORED")-1));

             break;

        default:
            /* Undefined command code */
            break;
        }
}

static enum test_return test_quit_impl(char *cmd) {
    union {
        char bytes[1024];
    } buffer;

    raw_command(buffer.bytes, sizeof(buffer.bytes),
        cmd, NULL, 0, NULL, 0);

    send_ascii_command(buffer.bytes);

    read_ascii_response(buffer.bytes, sizeof(buffer.bytes));
    validate_response(PROTOCOL_CMD_QUIT, buffer.bytes,
            PROTOCOL_RESPONSE_SUCCESS);

    /* Socket should be closed now, read should return 0 */
    assert(recv(sock, buffer.bytes, sizeof(buffer.bytes), 0) == 0);
    close(sock);
    sock = connect_server("127.0.0.1", port, false);

    return TEST_PASS;
}

static enum test_return test_quit(void) {
    return test_quit_impl(PROTOCOL_CMD_QUIT);
}

static enum test_return test_set_impl(const char *key, char *cmd) {
    union {
        char bytes[1024];
    } send, receive;
    char *value = "this is test";
    storage_command(send.bytes, sizeof(send.bytes), cmd,
                                 key, strlen(key), value, strlen(value),
                                 0, 0, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes,
            PROTOCOL_RESPONSE_SUCCESS);

    return TEST_PASS;
}

static enum test_return test_set(void) {
    return test_set_impl("test_set", PROTOCOL_CMD_SET);
}

static enum test_return test_add_impl(const char *key, char *cmd) {
    uint64_t value = 0xdeadbeefdeadcafe;
    union {
        char bytes[1024];
    } send, receive;
    storage_command(send.bytes, sizeof(send.bytes), cmd, key,
                                 strlen(key), (char *)&value, sizeof(value),
                                 0, 0, 0);

    /* Add should only work the first time */
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        send_ascii_command(send.bytes);
        if (ii == 0) {
            read_ascii_response(receive.bytes, sizeof(receive.bytes));
            validate_response(cmd, receive.bytes, 
                    PROTOCOL_RESPONSE_SUCCESS);
        } else {
            read_ascii_response(receive.bytes, sizeof(receive.bytes));
            validate_response(cmd,receive.bytes, 
                                     PROTOCOL_RESPONSE_KEY_EEXISTS);
        }
    }

    return TEST_PASS;
}

static enum test_return test_add(void) {
    return test_add_impl("test_add", PROTOCOL_CMD_ADD);
}


static enum test_return test_replace_impl(const char* key, char *cmd) {
    uint64_t value = 0xdeadbeefdeadcafe;
    union {
        char bytes[1024];
    } send, receive;

    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                                 key, strlen(key), &value, sizeof(value),
                                 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes,
                             PROTOCOL_RESPONSE_KEY_ENOSTORED);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_CMD_ADD,
                          key, strlen(key), &value, sizeof(value), 0, 0, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes,
                             PROTOCOL_RESPONSE_SUCCESS);

    len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                          key, strlen(key), &value, sizeof(value), 0, 0, 0);
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        send_ascii_command(send.bytes);
        read_ascii_response(receive.bytes, sizeof(receive.bytes));
        validate_response(PROTOCOL_CMD_REPLACE, receive.bytes,
                PROTOCOL_RESPONSE_SUCCESS);
    }

    return TEST_PASS;
}

static enum test_return test_replace(void) {
    return test_replace_impl("test_replace",
                                    PROTOCOL_CMD_REPLACE);
}

static enum test_return test_delete_impl(const char *key,char *cmd) {
    union {
        char bytes[1024];
    } send, receive;

    uint64_t value = 0xdeadbeefdeadcafe;
    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                             key, strlen(key), NULL, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes, 
                             PROTOCOL_RESPONSE_KEY_ENOENT);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_CMD_ADD,
                          key, strlen(key), &value, sizeof(value), 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes),
                      cmd, key, strlen(key), NULL, 0);
    send_ascii_command(send.bytes);

    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_DELETE, receive.bytes, 
            PROTOCOL_RESPONSE_SUCCESS);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes, 
                             PROTOCOL_RESPONSE_KEY_ENOENT);

    return TEST_PASS;
}

static enum test_return test_delete(void) {
    return test_delete_impl("test_delete",
                                   PROTOCOL_CMD_DELETE);
}

static enum test_return test_get_impl(const char *key, char *cmd) {
    union {
        char bytes[1024];
    } send, receive;

    uint64_t value = 0xdeadbeefdeadcafe;

    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                             key, strlen(key), NULL, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes, 
                             PROTOCOL_RESPONSE_KEY_ENOENT);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_CMD_ADD,
                          key, strlen(key), &value, sizeof(value),
                          0, 0, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes,
                             PROTOCOL_RESPONSE_SUCCESS);

    /* run a little pipeline test ;-) */
    len = 0;
    union {
        char bytes[1024];
    } temp;
    raw_command(temp.bytes, sizeof(temp.bytes),
            cmd, key, strlen(key), NULL, 0);

    send_ascii_command(temp.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes, 
            PROTOCOL_RESPONSE_SUCCESS);
    //read the value line also
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    read_ascii_response(receive.bytes, sizeof(receive.bytes));

    return TEST_PASS;
}

static enum test_return test_get(void) {
    return test_get_impl("test_get", PROTOCOL_CMD_GET);
}

static enum test_return test_incr_impl(const char* key, char *cmd) {
    union {
        char bytes[1024];
    } send, receive;

    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_CMD_ADD,
                                 key, strlen(key), "0", 1, 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));

    validate_response(PROTOCOL_CMD_ADD, receive.bytes, 
            PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), "1", 1);

    int ii, incr_val;
    for (ii = 0; ii < 10; ++ii) {
        send_ascii_command(send.bytes);
        read_ascii_response(receive.bytes, sizeof(receive.bytes));
	    incr_val = strtol(receive.bytes, NULL, 10);
        printf("received value is %s", receive.bytes);    
        assert(incr_val == ii+1);
    }
    return TEST_PASS;
}

static enum test_return test_incr(void) {
    return test_incr_impl("test_incr",
                                 PROTOCOL_CMD_INCREMENT);
}

static enum test_return test_decr_impl(const char* key, char *cmd) {
    union {
        char bytes[1024];
    } send, receive;

    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_CMD_ADD,
                                 key, strlen(key), "10", 2, 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes, 
        PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), "1", 1);
    int ii, decr_val;
    for (ii = 9; ii >= 0; --ii) {
        send_ascii_command(send.bytes);
        read_ascii_response(receive.bytes, sizeof(receive.bytes));
	    decr_val = strtol(receive.bytes, NULL, 10);
        assert(decr_val == ii);
    }

    return TEST_PASS;
}

static enum test_return test_decr(void) {
    return test_decr_impl("test_decr",
                                 PROTOCOL_CMD_DECREMENT);
}

static enum test_return test_version(void) {
    union {
        char bytes[1024];
    } buffer;

    raw_command(buffer.bytes, sizeof(buffer.bytes),
            PROTOCOL_CMD_VERSION,
            NULL, 0, NULL, 0);

    send_ascii_command(buffer.bytes);
    read_ascii_response(buffer.bytes, sizeof(buffer.bytes));
    validate_response(PROTOCOL_CMD_VERSION, buffer.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);
    return TEST_PASS;
}

static enum test_return test_flush_impl(const char *key, char *cmd) {
    union {
        char bytes[1024];
    } send, receive;

    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_CMD_ADD,
                                 key, strlen(key), "test", 4, 0, 0, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), cmd, 
                      NULL, 0, NULL, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes, 
            PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_CMD_GET,
                      key, strlen(key), NULL, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_GET, receive.bytes, 
                             PROTOCOL_RESPONSE_KEY_ENOENT);

    return TEST_PASS;
}

static enum test_return test_flush(void) {
    return test_flush_impl("test_flush",
                                  PROTOCOL_CMD_FLUSH);
}

uint64_t get_cas_value(char *a) {
    uint64_t cas;
    if (!strncmp("STORED", a, 6) && (cas = strtoull(a+7, NULL, 10)) != -1) {
        return cas;
    }
    return 0;
} 

uint64_t get_cas_value_from_gets(char *a) {
    char * b = a + strlen(a);
    while (*b-- != ' ');
    return strtoull(b+1, NULL, 10);
} 

static enum test_return test_cas(void) {
    union {
        char bytes[1024];
    } send, receive, tmp;

	size_t len;
    char *key = "FOO";

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_CMD_FLUSH,
                               NULL, 0, NULL, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_FLUSH, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);

    uint64_t value = 0xdeadbeefdeadcafe;
    len = storage_command(send.bytes, sizeof(send.bytes), PROTOCOL_CMD_CAS,
                          "FOO", 3, &value, sizeof(value), 0, 0, 0x7ffffff);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_CAS, receive.bytes, 
                             PROTOCOL_RESPONSE_KEY_ENOENT);
   
    len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_CMD_ADD,
                                 key, strlen(key), &value, sizeof(value), 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_CMD_GETS,
                               key, strlen(key), NULL, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    read_ascii_response(tmp.bytes, sizeof(tmp.bytes));
    read_ascii_response(tmp.bytes, sizeof(tmp.bytes));
 
    len = storage_command(send.bytes, sizeof(send.bytes), PROTOCOL_CMD_CAS,
                          "FOO", 3, &value, sizeof(value), 0, 0, get_cas_value_from_gets(receive.bytes));

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_CAS, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);

    len = storage_command(send.bytes, sizeof(send.bytes), PROTOCOL_CMD_CAS,
                          "FOO", 3, &value, sizeof(value), 0, 0, get_cas_value(receive.bytes));
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_CAS, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);
    return TEST_PASS;
}

static enum test_return test_concat_impl(const char *key, char *cmd) {
    union {
        char bytes[1024];
    } send, receive;
    const char *value = "world";
    
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd,
        key, strlen(key), value, strlen(value), 0, 0, 0);

    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes, 
                             PROTOCOL_RESPONSE_NOT_STORED);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_CMD_ADD,
                          key, strlen(key), value, strlen(value), 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_ADD, receive.bytes, 
                             PROTOCOL_RESPONSE_SUCCESS);

    len = storage_command(send.bytes, sizeof(send.bytes), cmd,
        key, strlen(key), value, strlen(value), 0, 0, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(cmd, receive.bytes,
            PROTOCOL_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes),
		  PROTOCOL_CMD_GET,
		  key, strlen(key), NULL, 0);
    send_ascii_command(send.bytes);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));
    validate_response(PROTOCOL_CMD_GET, receive.bytes, 
			 PROTOCOL_RESPONSE_SUCCESS);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));

    char *ptr = receive.bytes;
    assert(memcmp(ptr, value, strlen(value)) == 0);
    ptr += strlen(value);
    assert(memcmp(ptr, value, strlen(value)) == 0);
    read_ascii_response(receive.bytes, sizeof(receive.bytes));

    return TEST_PASS;
}

static enum test_return test_append(void) {
    return test_concat_impl("test_append",
                                   PROTOCOL_CMD_APPEND);
}

static enum test_return test_prepend(void) {
    return test_concat_impl("test_prepend",
                                   PROTOCOL_CMD_PREPEND);
}

static enum test_return test_verbosity(void) {
    union {
        char bytes[1024];
    } buffer;
    int ii;

    for (ii = 10; ii > -1; --ii) {
        raw_command(buffer.bytes, sizeof(buffer.bytes),
                PROTOCOL_CMD_VERBOSITY,
                "2", 1, NULL, 0);
        send_ascii_command(buffer.bytes);
        read_ascii_response(buffer.bytes, sizeof(buffer.bytes));
        validate_response(PROTOCOL_CMD_VERBOSITY, buffer.bytes,
                                 PROTOCOL_RESPONSE_SUCCESS);
    }
    return TEST_PASS;
}

typedef enum test_return (*TEST_FUNC)(void);
struct testcase {
    const char *description;
    TEST_FUNC function;
};

struct testcase testcases[] = {
    /* The following tests all run towards the same server */
    { "start_server", start_memcached_server },
    { "ascii_quit", test_quit},
    { "ascii_set", test_set },
    { "ascii_add", test_add },
    { "ascii_replace", test_replace },
    { "ascii_delete", test_delete },
    { "ascii_get", test_get },
    { "ascii_incr", test_incr },
    { "ascii_decr", test_decr },
    { "ascii_version", test_version },
    { "ascii_flush", test_flush },
    { "ascii_cas", test_cas },
    { "ascii_append", test_append },
    { "ascii_prepend", test_prepend },
    { "ascii_verbosity", test_verbosity },
    { "stop_server", stop_memcached_server },
    { NULL, NULL }
};

int main(int argc, char **argv)
{
    int exitcode = 0;
    int ii = 0, num_cases = 0;

    /* Use unbuffered stdio */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    for (num_cases = 0; testcases[num_cases].description; num_cases++) {
        /* Just counting */
    }

    printf("1..%d\n", num_cases);

    for (ii = 0; testcases[ii].description != NULL; ++ii) {
        fflush(stdout);
        enum test_return ret = testcases[ii].function();
        if (ret == TEST_SKIP) {
            fprintf(stdout, "ok # SKIP %d - %s\n", ii + 1, testcases[ii].description);
        } else if (ret == TEST_PASS) {
            fprintf(stdout, "ok %d - %s\n", ii + 1, testcases[ii].description);
        } else {
            fprintf(stdout, "not ok %d - %s\n", ii + 1, testcases[ii].description);
            exitcode = 1;
        }
        fflush(stdout);
    }

    return exitcode;
}
