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
	LIST_ENTRY(entry) entries;
};

LIST_HEAD(listhead, entry);

void setwritelist(struct listhead*, struct listhead*, struct entry*);
void sighandler(int);

int main(int argc, char **argv)
{
	int				sockfd, newsockfd, maxsockfd, dirsockfd, i, readval;
	unsigned short port;
	unsigned int	clilen;
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	char				s[MAX], msg[MAXMSGLEN], outmsg[MAX], topic[MAXTOPICLEN];
	fd_set readset, writeset;
	struct listhead readlist, writelist;

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

	if (connect(dirsockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
		perror("server: can't connect to directory");
		close(dirsockfd);
		exit(1);
	}

	// Write topic and port to directory (and keep socket open so the directory knows
	// the server is still up)
	snprintf(s, MAX, "s%s; %hu", topic, port);
	write(dirsockfd, s, MAX);


	// Continue with normal server operations

	LIST_INIT(&readlist);
	LIST_INIT(&writelist);

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

	listen(sockfd, 5);
	maxsockfd = sockfd;
	if (dirsockfd > maxsockfd) maxsockfd = dirsockfd;

	for (;;) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);

		// for fd in list
		LIST_FOREACH(currentry, &readlist, entries) {
			FD_SET(currentry->fd, &readset);
		}
		FD_SET(sockfd, &readset);
		FD_SET(dirsockfd, &readset);

		LIST_FOREACH(currentry, &writelist, entries) {
			FD_SET(currentry->fd, &writeset);
		}

		// select call here
		if ((i = select((maxsockfd + 1), &readset, &writeset, NULL, NULL)) > 0) {

			if (FD_ISSET(dirsockfd, &readset)) {
				readval = read(dirsockfd, s, MAX);
				if (readval < 0) {
					printf("server: directory connection unexpectedly closed\n");
					exit(0);
				}
				else if (readval == 0) {
					printf("server: directory rejected server (or shut down)\n");
					exit(0);
				}
				else {
					// This really shouldn't happen
					printf("server: received unexpected message from directory: %s", s);
				}
			}

			// Accept a new connection request
			if (FD_ISSET(sockfd, &readset)) {
				clilen = sizeof(cli_addr);
				newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");
					exit(1);
				} else {
					// When accepting, add entry with fd=newsockfd and name={'\0'}
					struct entry *newentry = malloc(sizeof(struct entry));
					newentry->fd = newsockfd;
					memset(newentry->name, '\0', MAXNAMELEN);
					LIST_INSERT_HEAD(&readlist, newentry, entries);
					if (maxsockfd < newsockfd) maxsockfd = newsockfd;

					snprintf(s, MAX, "Please input a username (max ten chars):");
					write(newsockfd, s, MAX);
				}
			}

			// for fd in readlist:
			currentry = LIST_FIRST(&readlist);
			while (currentry != NULL) {
				e2 = LIST_NEXT(currentry, entries);
				if (FD_ISSET(currentry->fd, &readset)) {
					// if name not set, accept msg as name, else send out msg
					/* Read the request from the client */
					readval = read(currentry->fd, s, MAX);
					if (readval < 0) {
						fprintf(stderr, "%s:%d Error reading from client, client connection removed\n", __FILE__, __LINE__);
						// also disconnects client below
					}
					if (readval <= 0) {
						// handle client disconnect
						close(currentry->fd);
						setwritelist(&readlist, &writelist, currentry);
						if (strncmp(currentry->name, "\0", MAXNAMELEN) != 0) {
							snprintf(outmsg, MAX, "%s has left the chat", currentry->name);
						}
						LIST_REMOVE(currentry, entries);
						free(currentry);
					}
					else if (strncmp(currentry->name, "\0", MAXNAMELEN) == 0) {
						if (strncmp(s, "\0", MAXNAMELEN) == 0) {
							snprintf(s, MAX, "An empty username is invalid, please enter a new name:");
							write(currentry->fd, s, MAX);
						}
						else {
							int repeatname = 0;
							struct entry *ent;
							LIST_FOREACH(ent, &readlist, entries) {
								if ((strncmp(ent->name, "\0", MAXNAMELEN) != 0) && (strncmp(s, ent->name, MAXNAMELEN-1) == 0)) repeatname = 1;
							}
							if (repeatname) {
								snprintf(s, MAX, "That username is already taken, please enter a new name:");
								write(currentry->fd, s, MAX);
							}
							else {
								// Add username
								if (snprintf(currentry->name, MAXNAMELEN, "%s", s) > (MAXNAMELEN - 1)) {
									snprintf(s, MAX, "Your name was truncated to %s", currentry->name);
									write(currentry->fd, s, MAX);
								}
								if (firstuser) {
									snprintf(s, MAX, "You are the first user to join the chat");
									write(currentry->fd, s, MAX);
									firstuser = 0;
								}
								snprintf(s, MAX, "You may now begin chatting (max message length is 87 chars)");
								write(currentry->fd, s, MAX);
								setwritelist(&readlist, &writelist, currentry);
								snprintf(outmsg, MAX, "%s has joined the chat", currentry->name);
							}
						}
					}
					else {
						// User has name and sent message
						// Add all sockets in read list except the writer
						setwritelist(&readlist, &writelist, currentry);

						// The check is really just to disable the truncation warning
						if (snprintf(msg, MAXMSGLEN, "%s", s) > (MAXMSGLEN - 1)) {
							snprintf(s, MAX, "Truncated: %s", msg);
							write(currentry->fd, s, MAX);
						}
						snprintf(outmsg, MAX, "%s: %s", currentry->name, msg);
					}
				}
				currentry = e2;
			}

			// for fd in writelist:
			currentry = LIST_FIRST(&writelist);
			while (currentry != NULL) {
				e2 = LIST_NEXT(currentry, entries);
				if (FD_ISSET(currentry->fd, &writeset)) {
					// Send message, then remove entry from writelist
					write(currentry->fd, outmsg, MAX);
					LIST_REMOVE(currentry, entries);
					free(currentry);
				}
				currentry = e2;
			}
		}
	}
}

void setwritelist(struct listhead *readlist, struct listhead *writelist, struct entry *currentry) {
	struct entry *readent;

	// Clear writelist beforehand
	struct entry *e1, *e2;
	e1 = LIST_FIRST(writelist);
	while (e1 != NULL) {
		e2 = LIST_NEXT(e1, entries);
		LIST_REMOVE(e1, entries);
		free(e1);
		e1 = e2;
	}

	LIST_FOREACH(readent, readlist, entries) {
		if (readent != currentry && strncmp(readent->name, "\0", MAXNAMELEN) != 0) {
			struct entry *newentry = malloc(sizeof(struct entry));
			newentry->fd = readent->fd;
			LIST_INSERT_HEAD(writelist, newentry, entries);
		}
	}
}

void sighandler(int signo) {
	printf("\nCaught signal: %d\n", signo);
	exit(0);
}
