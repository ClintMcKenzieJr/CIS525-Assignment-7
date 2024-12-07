#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "inet.h"
#include "common.h"

// TLS certificate files, located in /certificates-- individual server key and certificate files are defined in main
#define CAFILE "openssl/rootCACert.pem" //set file location here
#define LOOP_CHECK(rval, cmd) \
	do {                  \
		rval = cmd;   \
	} while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)
int TLSflag = 1; //whether or not server is certified 

// Prevents an unnecessary warning
size_t strnlen(const char *s, size_t maxlen);

struct entry {
	int fd;
	char name[MAXNAMELEN];
	char *inptr, *outptr;
	char inBuffer[MAX], outBuffer[MAX];
	gnutls_session_t session; //TLS session
	LIST_ENTRY(entry) entries;
};

LIST_HEAD(listhead, entry);

int nonblockread(struct entry*);
void setoutmsgs(struct listhead*, struct entry*, char*);
void sighandler(int);

int main(int argc, char **argv)
{
	int		sockfd, newsockfd, maxsockfd, dirsockfd, i, j, k, nwritten;
	unsigned short	port;
	unsigned int	clilen;
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	char msg[MAXMSGLEN], outmsg[MAX], topic[MAXTOPICLEN];
	fd_set readset, writeset;
	struct listhead clilist;
	struct entry *currentry, *e2;
	int firstuser = 1;
	

	// TLS credential Initialization
	gnutls_session_t 	dSession;
	gnutls_certificate_credentials_t x509_cred;
	char keyFile[MAX] = {'\0'};
	char certFile[MAX] = {'\0'};

	if (gnutls_global_init() < 0){ 
		perror("chat server: TLS error: can't global init gnuTLS");
		exit(1);
	}
	if (gnutls_certificate_allocate_credentials(&x509_cred) < 0){
		perror("chat server: TLS error: failed to allocated x509 credentials");
		gnutls_global_deinit();
		exit(1);
	}
	if (gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM) < 0){
		perror("chat server: TLS error: failed to set CA file");
		gnutls_global_deinit();
		gnutls_certificate_free_credentials(x509_cred);
		exit(1);
	}
	
	//user input parse
	if (argc != 3) {
		printf("Two arguments required: topic and port\n");
		exit(0);
	}

	// Issue warning to server but continue (since it won't break anything)
	if (strnlen(argv[1], MAXTOPICLEN) > MAXTOPICLEN - 1) {
		printf("Topic name too long, will be truncated\n");
	}

	snprintf(topic, MAXTOPICLEN, "%s", argv[1]);

	if (sscanf(argv[2], "%hu", &port) != 1) {
		printf("Could not parse port number\n");
		exit(0);
	}

	// Checking topic name
	if (strchr(topic, ';') != NULL || strchr(topic, ',') != NULL) {
		printf("Please do not use , or ; in topic names\n");
		exit(0);
	}

	// register with directory (and keep connection open)
	memset((char*) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family		= AF_INET;
	dir_addr.sin_addr.s_addr	= inet_addr(DIR_HOST_ADDR);
	dir_addr.sin_port		= htons(DIR_TCP_PORT);

	if ((dirsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}
	
	// TODO / FIXME : We probably don't need to set the Server -> Directory socket to nonblocking, right?
	// If we don't need to, then there should be a comment here about why we don't need it to be nonblocking

	if (connect(dirsockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
		perror("server: can't connect to directory");
		close(dirsockfd);
		exit(1);
	}

	// initialize TLS session- this is set as Client towards directory server
	if (gnutls_init(&dSession, GNUTLS_CLIENT) < 0) {
		perror("chat server: TLS error: failed to initialize TLS session");
		exit(1);
	}
	if(gnutls_credentials_set(dSession, GNUTLS_CRD_CERTIFICATE, x509_cred)<0 ){
		perror("chat server: TLS error: failed credentials set");
        exit(1);
	}
	if(gnutls_set_default_priority(dSession) < 0){
        perror("chat server: TLS error: failed priority set");
        exit(1);
    }

	// TLS Handshake with Directory Server
	gnutls_transport_set_int(dSession, dirsockfd);
	int handshake;
	LOOP_CHECK(handshake, gnutls_handshake(dSession));
	if (handshake < 0){
		// TLS Handshake error handling
		fprintf(stderr, "%s:%d Directory Handshake failed: %s\n", __FILE__, __LINE__, gnutls_strerror(handshake));
		gnutls_datum_t out;
		int type = gnutls_certificate_type_get(dSession);
		unsigned status = gnutls_session_get_verify_cert_status(dSession);
		gnutls_certificate_verification_status_print(status, type, &out, 0);
		fprintf(stderr, "cert verify output: %s\n", out.data);
		gnutls_free(out.data);
		close(dirsockfd);
		gnutls_global_deinit();
		gnutls_certificate_free_credentials(x509_cred);
		exit(1);
	}
	else {
          fprintf(stderr, "chat server: Directory Handshake completed!\n");
    }

	// Write topic and port to directory (and keep socket open so the directory knows
	// the server is still up)
	snprintf(outmsg, MAX, "s%s; %hu", topic, port);
	gnutls_record_send(dSession, outmsg, MAX);

	// TLS: Setting Certified server:
	if (0 == strncmp("Birds", topic, MAXTOPICLEN)){
		snprintf(keyFile, MAX, "openssl/serverBirdsKey.pem");
		snprintf(certFile, MAX, "openssl/serverBirdsCert.pem");
	}
	else if (0 == strncmp("Computers", topic, MAXTOPICLEN)){
		snprintf(keyFile, MAX, "openssl/serverComputersKey.pem");
		snprintf(certFile, MAX, "openssl/serverComputersCert.pem");
	}
	else if (0 == strncmp("Cool Things", topic, MAXTOPICLEN)){
		snprintf(keyFile, MAX, "openssl/serverCoolThingsKey.pem");
		snprintf(certFile, MAX, "openssl/serverCoolThingsCert.pem");
	}
	else if (0 == strncmp("Flipper Hacks", topic, MAXTOPICLEN)){
		snprintf(keyFile, MAX, "openssl/serverFlipperHacksKey.pem");
		snprintf(certFile, MAX, "openssl/serverFlipperHacksCert.pem");
	}
	else if (0 == strncmp("Food", topic, MAXTOPICLEN)){
		snprintf(keyFile, MAX, "openssl/serverFoodKey.pem");
		snprintf(certFile, MAX, "openssl/serverFoodCert.pem");
	}
	else { //server is not certifid
		TLSflag = 0;
	}

	if(TLSflag){ //Set key and cert file
		if (gnutls_certificate_set_x509_key_file(x509_cred, certFile, keyFile, GNUTLS_X509_FMT_PEM) < 0){ //pg 169
			perror("directoryServer -- TLS error: can't set certificate");
			gnutls_global_deinit();
			gnutls_certificate_free_credentials(x509_cred);
			exit(1);
  		}

	}
	

	// Continue with normal server operations

	LIST_INIT(&clilist);

	signal(SIGINT, sighandler);

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port		= htons(port);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		exit(1);
	}

	/* now we're ready to start accepting client connections */
	listen(sockfd, 5);

	for (;;) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(sockfd, &readset);

		maxsockfd = sockfd;

		LIST_FOREACH(currentry, &clilist, entries) {
			FD_SET(currentry->fd, &readset);
			// TODO / FIXME: Test this to make sure it works
			//FD_SET(currentry->fd, &writeset);
			if (&(currentry->outBuffer[MAX]) - currentry->outptr > 0) {
				FD_SET(currentry->fd, &writeset);
			}
			if (maxsockfd < currentry->fd) {maxsockfd = currentry->fd;}
		}

		if ((i=select(maxsockfd+1, &readset, &writeset, NULL, NULL)) > 0) {
			/* Handle listening socket */
			if (FD_ISSET(sockfd, &readset)) {
				clilen = sizeof(cli_addr);
				newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");
				} else {
					if (fcntl(newsockfd, F_SETFL, O_NONBLOCK) != 0 ) {
						perror("server: couldn't set new client socket to nonblocking");
						close(newsockfd);
					} else {
						// Handle successful connection (set up new entry)
						struct entry *newentry = malloc(sizeof(struct entry));
						newentry->fd = newsockfd;
						memset(newentry->name, '\0', MAXNAMELEN);
						memset(newentry->inBuffer, '\0', MAX);
						memset(newentry->outBuffer, '\0', MAX);
						newentry->inptr = newentry->inBuffer;
						newentry->outptr = newentry->outBuffer;

						
						//gnuTLS session setup if user is verified 
						if(TLSflag){
							if(gnutls_init(&newentry->session, GNUTLS_SERVER) < 0){
								perror("directoryServer -- TLS error: failed to initialize session");
								close(newsockfd);
								free(newentry);
								continue;
							}
							if(gnutls_credentials_set(newentry->session, GNUTLS_CRD_CERTIFICATE, x509_cred) < 0){
								perror("directoryServer -- TLS error: failed to set credentials");
								close(newsockfd);
								free(newentry);
								continue;
							}
							if(gnutls_set_default_priority(newentry->session) < 0){
								perror("directoryServer -- TLS error: failed priority set");
								close(newsockfd);
								free(newentry);
								continue;
							}

							// Set up transport layer
							gnutls_transport_set_int(newentry->session, newsockfd);
							
							//TLS handshake with client
							int handshake;
							LOOP_CHECK(handshake, gnutls_handshake(newentry->session));
							if (handshake < 0 ) {
								//handshake failed, disconnect client
								close(newsockfd);
								free(newentry);

								// TLS Handshake error handling
								fprintf(stderr, "%s:%d Client Handshake failed: %d:%s\n", __FILE__, __LINE__, handshake, gnutls_strerror(handshake));
								gnutls_datum_t out;
								int type = gnutls_certificate_type_get(newentry->session);
								unsigned status = gnutls_session_get_verify_cert_status(newentry->session);
								gnutls_certificate_verification_status_print(status, type, &out, 0);
								fprintf(stderr, "cert verify output: %s\n", out.data);
								gnutls_free(out.data);

								continue;
							}
							else { //successful handshake connection! add Client to list and begin communication
								fprintf(stderr, "chat Server: Client Handshake completed!\n");
							}
							
						
						}
						LIST_INSERT_HEAD(&clilist, newentry, entries);
						snprintf(newentry->outBuffer, MAX, "Please input a username (max ten chars):");
					}
				}
			}

			// Reading from clients
			currentry = LIST_FIRST(&clilist);
			while (currentry != NULL) {
				e2 = LIST_NEXT(currentry, entries);
				if (FD_ISSET(currentry->fd, &readset)) {
					// nonblockread returns 1 on finished receiving msg, 0 on partial read, -1 on failure or closed connection
					if ((j=nonblockread(currentry)) == 1) {
						// Client has no set name, name will be set based on message
						if (strncmp(currentry->name, "\0", MAXNAMELEN) == 0) {
							if (strncmp(currentry->inBuffer, "\0", MAXNAMELEN) == 0) {
								snprintf(currentry->outBuffer, MAX, "An empty username is invalid, please enter a new name:");
								currentry->outptr = currentry->outBuffer;
							}
							else {
								int repeatname = 0;
								struct entry *ent;
								LIST_FOREACH(ent, &clilist, entries) {
									if ((strncmp(ent->name, "\0", MAXNAMELEN) != 0) && (strncmp(currentry->inBuffer, ent->name, MAXNAMELEN-1) == 0)) {
										repeatname = 1;
									}
								}
								if (repeatname) {
									snprintf(currentry->outBuffer, MAX, "That username is already taken, please enter a new name:");
									currentry->outptr = currentry->outBuffer;
								}
								else {
									// Add username
									// This line has a truncation warning.  It's intended to truncate if the input is too large, so the warning is expected and fine.
									snprintf(currentry->name, MAXNAMELEN, "%s", currentry->inBuffer);
									if (firstuser) {
										snprintf(currentry->outBuffer, MAX, "You are the first user to join the chat\nYou may now begin chatting (max msg length is 87 chars)");
										firstuser = 0;
									} else {
										snprintf(currentry->outBuffer, MAX, "You may now begin chatting (max message length is 87 chars)");
									}
									currentry->outptr = currentry->outBuffer;
									snprintf(outmsg, MAX, "%s has joined the chat", currentry->name);
									setoutmsgs(&clilist, currentry, outmsg);
								}
							}
						} else {
							// User has name and sent message
							if (snprintf(msg, MAXMSGLEN, "%s", currentry->inBuffer) > (MAXMSGLEN - 1)) {
								snprintf(currentry->outBuffer, MAX, "Truncated: %s", msg);
								currentry->outptr = currentry->outBuffer;
							}
							snprintf(outmsg, MAX, "%s: %s", currentry->name, msg);
							// Send message to all clients except the writer
							setoutmsgs(&clilist, currentry, outmsg);
						}
						// Reset client's buffer and pointer
						memset(currentry->inBuffer, '\0', MAX);
						currentry->inptr = currentry->inBuffer;
					} else if (j == -1) { //FIX -- close TLS here
						// Close socket, free entry, remove from list
						close(currentry->fd);
						if (strncmp(currentry->name, "\0", MAXNAMELEN) != 0) {
							snprintf(outmsg, MAX, "%s has left the chat", currentry->name);
							setoutmsgs(&clilist, currentry, outmsg);
						}
						LIST_REMOVE(currentry, entries);
						free(currentry);
					}
					// Do nothing on partial read
				}
				currentry = e2;
			}

			// Writing to clients
			currentry = LIST_FIRST(&clilist);
			while (currentry != NULL) {
				e2 = LIST_NEXT(currentry, entries);
				if (FD_ISSET(currentry->fd, &writeset) && ((k = &(currentry->outBuffer[MAX]) - currentry->outptr) > 0)) {
					// Send message
					if(!TLSflag) { //non TLS write
						if ((nwritten = write(currentry->fd, currentry->outptr, k)) < 0) {
							if (errno != EWOULDBLOCK && errno != EAGAIN) {
								perror("server: write error on client socket");
								// Close socket, free entry, remove from list
								close(currentry->fd);
								if (strncmp(currentry->name, "\0", MAXNAMELEN) != 0) {
									snprintf(outmsg, MAX, "%s has left the chat", currentry->name);
									setoutmsgs(&clilist, currentry, outmsg);
								}
								LIST_REMOVE(currentry, entries);
								free(currentry);
							}
						} else {
							currentry->outptr += nwritten;
						}
					}
					else { //TLS write
						if ((nwritten = gnutls_record_send(currentry->session, currentry->outptr, k)) < 0) {
							if (errno != EWOULDBLOCK && errno != GNUTLS_E_INTERRUPTED && errno != GNUTLS_E_AGAIN) {
								perror("server: write error on client socket");
								// Close socket, free entry, remove from list
								//FIX --add TLS memory cleanup
								close(currentry->fd);
								if (strncmp(currentry->name, "\0", MAXNAMELEN) != 0) {
									snprintf(outmsg, MAX, "%s has left the chat", currentry->name);
									setoutmsgs(&clilist, currentry, outmsg);
								}
								LIST_REMOVE(currentry, entries);
								free(currentry);
							}
						} else {
							currentry->outptr += nwritten;
						}
					}
				}
				currentry = e2;
			}
		} /* end of if select */
	} /* end of infinite for loop */
	//FIX-- Add TLS memory clean up here
	close(sockfd);

	//return or exit(0) is implied; no need to do anything because main() ends
}

// Attempts to read from a given client's socket
// Returns 1 on reading full message, 0 on partial read, and -1 on read failure or closed connection
int nonblockread(struct entry *e) {
	int nread = 0;
	if(!TLSflag){ //non TLS read
		if ((nread = read(e->fd, e->inptr, &e->inBuffer[MAX] - e->inptr)) < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				return 0; // msg not fully received; shouldn't happen, but best to be safe
			}
			fprintf(stderr, "%s:%d Error reading from client, client connection removed\n", __FILE__, __LINE__);
			return -1;
		}
	}
	else { //TLS read
		nread = gnutls_record_recv(e->session, e->inptr, &e->inBuffer[MAX] - e->inptr);
		if (errno == EWOULDBLOCK || errno == GNUTLS_E_INTERRUPTED || errno == GNUTLS_E_AGAIN) {
			return 0; // msg not fully received; shouldn't happen, but best to be safe
		}
		fprintf(stderr, "%s:%d TLS Error reading from client, client connection removed %d\n", __FILE__, __LINE__, errno);
		return -1;
	}
	if (nread > 0) {
		e->inptr += nread;
		// Need to check if msg fully received
		// Client always writes MAX
		if (&(e->inBuffer[MAX]) == e->inptr) {
			return 1;
		}
		return 0;
	}
	// read returned 0, closed connection
	return -1;
}

// Sets all clients' out buffers to the given message, other than the specified client
void setoutmsgs(struct listhead *clilist, struct entry *currentry, char *outmsg) {
	struct entry *readent;

	LIST_FOREACH(readent, clilist, entries) {
		if (readent != currentry && strncmp(readent->name, "\0", MAXNAMELEN) != 0) {
			snprintf(readent->outBuffer, MAX, "%s", outmsg);
			readent->outptr = readent->outBuffer;
		}
	}
}

void sighandler(int signo) {
	printf("\nCaught signal: %d\n", signo);
	exit(0);
}