#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "inet.h"
#include "common.h"

// TLS certificate files, located in /certificates
#define CAFILE "openssl/rootCACert.pem" //set file location here
#define LOOP_CHECK(rval, cmd) \
	do {                  \
		rval = cmd;   \
	} while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

// Prevents an unnecessary warning
size_t strnlen(const char *s, size_t maxlen);

int main()
{
	char s[MAX], input[MAX-2] = {'\0'};
	fd_set			readset;
	int				sockfd;
	struct sockaddr_in dir_addr, serv_addr;
	int				nread;	/* number of characters */
	size_t				msglen;
	unsigned short port;
	unsigned long ip_addr;
	//gnutls_priority_t priority_cache;
	
	// TLS Initialization
	gnutls_session_t 	session;
	gnutls_certificate_credentials_t x509_cred;

	if (gnutls_global_init() < 0){ 
		perror("client: TLS error: can't global init gnuTLS");
		exit(1);
	}
	if (gnutls_certificate_allocate_credentials(&x509_cred) < 0){
		perror("client: TLS error: failed to allocated x509 credentials");
		gnutls_global_deinit();
		exit(1);
	}
	if (gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM) < 0){
		perror("client: TLS error: failed to set CA file");
		gnutls_global_deinit();
		gnutls_certificate_free_credentials(x509_cred);
		exit(1);
	}

	/* Set up the address of the directory to be contacted. */
	memset((char *) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family			= AF_INET;
	dir_addr.sin_addr.s_addr		= inet_addr(DIR_HOST_ADDR);
	dir_addr.sin_port			= htons(DIR_TCP_PORT);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		exit(1);
	}

	/* Connect to the directory. */
	if (connect(sockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
		perror("client: can't connect to directory");
		exit(1);
	}

	// initialize TLS session
	if (gnutls_init(&session, GNUTLS_CLIENT) < 0) {
		perror("client: TLS error: failed to initialize TLS session");
		exit(1);
	}
	if(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred)<0 ){
		perror("client: TLS error: failed credentials set");
        exit(1);
	}
	if(gnutls_set_default_priority(session) < 0){
        perror("client: TLS error: failed priority set");
        exit(1);
    }


	// TLS Handshake with Directory Server
	gnutls_transport_set_int(session, sockfd);
	int handshake;
	LOOP_CHECK(handshake, gnutls_handshake(session));
	if (handshake < 0){
		// TLS Handshake error handling
		fprintf(stderr, "%s:%d Directory Handshake failed: %d:%s\n", __FILE__, __LINE__, handshake, gnutls_strerror(handshake));
		gnutls_datum_t out;
		int type = gnutls_certificate_type_get(session);
		unsigned status = gnutls_session_get_verify_cert_status(session);
		gnutls_certificate_verification_status_print(status, type, &out, 0);
		fprintf(stderr, "cert verify output: %s\n", out.data);
		gnutls_free(out.data);
		close(sockfd);
		gnutls_global_deinit();
		gnutls_certificate_free_credentials(x509_cred);
		exit(1);
	}
	else {
          fprintf(stderr, "chat client: Directory Handshake completed!\n");
    }

	// Request servers, wait to read, then wait for input, then write and wait to read
	// Request server list
	snprintf(s, MAX, "cl");
	gnutls_record_send(session, s, MAX);

	// Read server list
	if ((nread = gnutls_record_recv(session, s, MAX)) < 0) {
		perror("Error reading server list from directory server");
		exit(1);
	} else if (nread == 0) {
		printf("Directory disconnected, shutting down client\n");
		exit(0);
	} else {
		printf("Servers: %s\n", s);
	}

	// Get and send user input (requesting specified server info)
	if (fgets(input, MAX - 2, stdin) == NULL) {
		printf("Error reading or parsing user input\n");
	}
	snprintf(s, MAX, "cr%s", input);

	gnutls_record_send(session, s, MAX);

	// Read server connection info
	if ((nread = gnutls_record_recv(session, s, MAX)) < 0) {
		printf("Error reading server connection info from directory server\n");
		exit(1);
	} else if (nread == 0) {
		printf("Directory disconnected, shutting down client\n");
		exit(0);
	} else {
		// Parsing
		if (sscanf(s, "%lu;%hu", &ip_addr, &port) != 2) {
			printf("Input parsing failed, closing client\n");
			exit(1);
		}
		gnutls_bye(session, GNUTLS_SHUT_RDWR);
		close(sockfd);
		gnutls_deinit(session);
	}


	// Resume normal operations from Assignment 3

	// Connect to server

	/* Set up the address of the server to be contacted. */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family			= AF_INET;
	serv_addr.sin_addr.s_addr		= ip_addr;
	serv_addr.sin_port			= htons(port);

	/* Connect to the server. */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket (2)");
		exit(1);
	}

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to server");
		exit(1);
	}

	if (gnutls_init(&session, GNUTLS_CLIENT) < 0) {
		perror("client: TLS error: failed to initialize TLS session");
		exit(1);
	}
	if(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred)<0 ){
		perror("client: TLS error: failed credentials set");
        exit(1);
	}
	if(gnutls_set_default_priority(session) < 0){
        perror("client: TLS error: failed priority set");
        exit(1);
    }

	// TLS Handshake with chat Server
	gnutls_transport_set_int(session, sockfd);

	if ((handshake = gnutls_handshake(session)) < 0){
		fprintf(stderr, "%s:%d Server Handshake failed: %d:%s\n", __FILE__, __LINE__, handshake, gnutls_strerror(handshake));
		close(sockfd);
		gnutls_global_deinit();
		gnutls_certificate_free_credentials(x509_cred);
		exit(1);
	}
	else {
		fprintf(stderr, "chat client: Server Handshake completed!\n");
	}

	for(;;) {

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		if (select(sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				if (fgets(s, MAX, stdin) != NULL) {
					/* Send the user's message to the server */
					// Handles that pesky extra newline
					msglen = strnlen(s, MAX);
					if (msglen > 0 && s[msglen - 1] == '\n') {
						s[msglen - 1] = '\0';
					}
					gnutls_record_send(session, s, MAX);
				} else {
					printf("Error reading or parsing user input\n");
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				if ((nread = gnutls_record_recv(session, s, MAX)) < 0) {
					perror("Error reading from server\n");
					exit(1);
				} else if (nread == 0) {
					printf("Server disconnected, shutting down client\n");
					exit(0);
				} else {
					printf("%s\n", s);
				}
			}
		}
	}
	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	close(sockfd);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_deinit(session);
	gnutls_global_deinit();
}
