#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"

// Prevents an unnecessary warning
size_t strnlen(const char *s, size_t maxlen);

struct entry {
	int fd;
	char name[MAXNAMELEN];
	char *inptr, *outptr;
	char inBuffer[MAX], outBuffer[MAX];
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

	// Write topic and port to directory (and keep socket open so the directory knows
	// the server is still up)
	snprintf(outmsg, MAX, "s%s; %hu", topic, port);
	write(dirsockfd, outmsg, MAX);


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
			if (&(currentry->outBuffer[MAX]) - currentry->outptr) > 0) {
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
					} else if (j == -1) {
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
				currentry = e2;
			}
		} /* end of if select */
	} /* end of infinite for loop */

	close(sockfd);

	//return or exit(0) is implied; no need to do anything because main() ends
}

// Attempts to read from a given client's socket
// Returns 1 on reading full message, 0 on partial read, and -1 on read failure or closed connection
int nonblockread(struct entry *e) {
	int nread = 0;
	if ((nread = read(e->fd, e->inptr, &e->inBuffer[MAX] - e->inptr)) < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			return 0; // msg not fully received; shouldn't happen, but best to be safe
		}
		fprintf(stderr, "%s:%d Error reading from client, client connection removed\n", __FILE__, __LINE__);
		return -1;
	} else if (nread > 0) {
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