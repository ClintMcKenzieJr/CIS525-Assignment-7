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

struct svr_entry {
	int fd;
	char topic[MAXTOPICLEN];
	unsigned short port;
	unsigned long ip_addr;
	LIST_ENTRY(svr_entry) svr_entries;
};

struct cli_entry {
	int fd;
	char message[MAX];
	LIST_ENTRY(cli_entry) cli_entries;
};

// To be used for all new connections which have not been identified yet
struct uncat_entry {
	int fd;
	unsigned long ip_addr;
	LIST_ENTRY(uncat_entry) uncat_entries;
};

LIST_HEAD(svr_listhead, svr_entry);
LIST_HEAD(cli_listhead, cli_entry);
LIST_HEAD(uncat_listhead, uncat_entry);

void sighandler(int);

int main(int argc, char **argv)
{
	int				sockfd, newsockfd, maxsockfd, i, repeat_name;
	unsigned int	clilen;
	unsigned short port = 0;
	struct sockaddr_in cli_addr, serv_addr;
	char				s[MAX], outmsg[MAX], tempmsg[MAX], topic[MAXTOPICLEN];
	fd_set readset, writeset;
	struct svr_listhead svr_list;
	struct cli_listhead cli_list;
	struct uncat_listhead uncat_list;

	struct svr_entry *svr_currentry, *svr_e2;
	struct cli_entry *cli_currentry, *cli_e2;
	struct uncat_entry *uncat_currentry, *uncat_e2;
	int numServers = 0;

	LIST_INIT(&svr_list);
	LIST_INIT(&cli_list);
	LIST_INIT(&uncat_list);

	signal(SIGINT, sighandler);

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("directory: can't open stream socket");
		exit(1);
	}

	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("directory: can't set stream socket address reuse option");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(DIR_HOST_ADDR);
	serv_addr.sin_port		= htons(DIR_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("directory: can't bind local address");
		exit(1);
	}

	listen(sockfd, 5);
	maxsockfd = sockfd;

	for (;;) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		maxsockfd = sockfd;

		// Listening to all uncategorized connections
		LIST_FOREACH(uncat_currentry, &uncat_list, uncat_entries) {
			FD_SET(uncat_currentry->fd, &readset);
			if (uncat_currentry->fd > maxsockfd) maxsockfd = uncat_currentry->fd;
		}
		// Checking all servers to see if they have disconnected
		LIST_FOREACH(svr_currentry, &svr_list, svr_entries) {
			FD_SET(svr_currentry->fd, &readset);
			if (svr_currentry->fd > maxsockfd) maxsockfd = svr_currentry->fd;
		}
		// Checking listening socket
		FD_SET(sockfd, &readset);
		// Checking all clients for messages
		LIST_FOREACH(cli_currentry, &cli_list, cli_entries) {
			FD_SET(cli_currentry->fd, &readset);
			if (cli_currentry->fd > maxsockfd) maxsockfd = cli_currentry->fd;
		}

		// Write to all clients who have a message waiting
		LIST_FOREACH(cli_currentry, &cli_list, cli_entries) {
			if (strncmp(cli_currentry->message, "\0", MAX) != 0) {
				FD_SET(cli_currentry->fd, &writeset);
				if (cli_currentry->fd > maxsockfd) maxsockfd = cli_currentry->fd;
			}
		}

		// select call here
		if ((i = select((maxsockfd + 1), &readset, &writeset, NULL, NULL)) > 0) {

			// Accept a new connection request
			if (FD_ISSET(sockfd, &readset)) {
				clilen = sizeof(cli_addr);
				newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");
					exit(1);
				} else {
					// When accepting, add entry to uncat_list
					struct uncat_entry *newentry = malloc(sizeof(struct uncat_entry));
					newentry->fd = newsockfd;
					newentry->ip_addr = cli_addr.sin_addr.s_addr;
					LIST_INSERT_HEAD(&uncat_list, newentry, uncat_entries);
				}
			}

			// for fd in svr_list:
			svr_currentry = LIST_FIRST(&svr_list);
			while (svr_currentry != NULL) {
				svr_e2 = LIST_NEXT(svr_currentry, svr_entries);
				if (FD_ISSET(svr_currentry->fd, &readset)) {
					// Check if the server connection has closed
					if (read(svr_currentry->fd, s, MAX) <= 0) {
						// Handle server disconnect/shutdown
						numServers--;
						close(svr_currentry->fd);
						LIST_REMOVE(svr_currentry, svr_entries);
						free(svr_currentry);
					}
				}
				svr_currentry = svr_e2;
			}

			// for fd in cli_list:
			cli_currentry = LIST_FIRST(&cli_list);
			while (cli_currentry != NULL) {
				cli_e2 = LIST_NEXT(cli_currentry, cli_entries);
				// If client sent a message
				if (FD_ISSET(cli_currentry->fd, &readset)) {
					// Read, determine type (if not starting with "cr" or asking for nonexistent server or read=0, close)
					if (read(cli_currentry->fd, s, MAX) <= 0) {
						close(cli_currentry->fd);
						LIST_REMOVE(cli_currentry, cli_entries);
						free(cli_currentry);
					}
					else if (strncmp(s, "cr", 2) == 0) {
						// This should always parse correctly, since it should be formatted correctly
						// on the client's end
						if (sscanf(s, "cr%[^\n]", topic) != 1) {
							printf("Failed to parse server info\n");
							exit(1);
						}
						svr_currentry = LIST_FIRST(&svr_list);
						while (svr_currentry != NULL) {
							svr_e2 = LIST_NEXT(svr_currentry, svr_entries);
							if (strncmp(topic, svr_currentry->topic, MAXTOPICLEN-1) == 0) {
								snprintf(cli_currentry->message, MAX, "%lu;%hu", svr_currentry->ip_addr, svr_currentry->port);
								svr_e2 = NULL;
							}
							svr_currentry = svr_e2;
						}
						// Setting the message field will add the client to the write set next time around
						// Or, if the given topic doesn't exist, close the connection without writing
						if (strncmp(cli_currentry->message, "\0", MAX) == 0) {
							close(cli_currentry->fd);
							LIST_REMOVE(cli_currentry, cli_entries);
							free(cli_currentry);
						}
					}
					else {
						// Unexpected client message (really shouldn't be possible)
						close(cli_currentry->fd);
						LIST_REMOVE(cli_currentry, cli_entries);
						free(cli_currentry);
					}
				}
				// If client is ready to be sent a message
				else if (FD_ISSET(cli_currentry->fd, &writeset)) {
					write(cli_currentry->fd, cli_currentry->message, MAX);
					// Prevents the socket from being added to the writeset in the next iteration
					memset(cli_currentry->message, '\0', MAX);
				}
				cli_currentry = cli_e2;
			}

			// for fd in uncat_list:
			uncat_currentry = LIST_FIRST(&uncat_list);
			while (uncat_currentry != NULL) {
				uncat_e2 = LIST_NEXT(uncat_currentry, uncat_entries);
				if (FD_ISSET(uncat_currentry->fd, &readset)) {
					// Socket closed or invalid first message (first messages should always be at least 2 chars long)
					if (read(uncat_currentry->fd, s, MAX) <= 0 || strnlen(s, MAX) < 2) {
						// Close and forget socket
						close(uncat_currentry->fd);
						LIST_REMOVE(uncat_currentry, uncat_entries);
						free(uncat_currentry);
					}
					// Determine type
					// A client's first message will always be "cl"
					if (strncmp(s, "cl", 2) == 0) {
						struct cli_entry *newentry = malloc(sizeof(struct cli_entry));
						newentry->fd = uncat_currentry->fd;

						memset(outmsg, '\0', MAX);
						memset(tempmsg, '\0', MAX);
						i = 1;
						svr_currentry = LIST_FIRST(&svr_list);
						while (svr_currentry != NULL) {
							svr_e2 = LIST_NEXT(svr_currentry, svr_entries);
							// Checks if outmsg has enough space
							if ((strnlen(outmsg, MAX) + MAXTOPICLEN + 2 <= MAX) || 
							    (i == 5 && strnlen(outmsg, MAX) + MAXTOPICLEN <= MAX)) {
								//strncat(outmsg, svr_currentry->topic, MAXTOPICLEN);
								snprintf(tempmsg, strnlen(outmsg, MAX) + MAXTOPICLEN, "%s%s", outmsg, svr_currentry->topic);
								snprintf(outmsg, strnlen(outmsg, MAX) + MAXTOPICLEN, "%s", tempmsg);
								if (i != numServers) strncat(outmsg, ", ", 3);
							}
							svr_currentry = svr_e2;
							i++;
						}
						snprintf(newentry->message, MAX, "%s", outmsg);
						LIST_INSERT_HEAD(&cli_list, newentry, cli_entries);
						LIST_REMOVE(uncat_currentry, uncat_entries);
						free(uncat_currentry);
					}
					// A server's first (and only) message will always start with 's'
					else if (strncmp(s, "s", 1) == 0) {
						// This should always parse correctly, since it should be formatted correctly
						// on the server's end
						if (sscanf(s, "s%[^;]; %hu", topic, &port) != 2) {
							printf("Failed to parse server info\n");
							exit(1);
						}
						repeat_name = 0;
						LIST_FOREACH(svr_e2, &svr_list, svr_entries) {
							if (strncmp(topic, svr_e2->topic, MAXTOPICLEN-1) == 0) {
								repeat_name = 1;
							}
						}

						if (repeat_name || numServers >= 5) {
							// Close the socket; the server will know to shut down
							close(uncat_currentry->fd);
							LIST_REMOVE(uncat_currentry, uncat_entries);
							free(uncat_currentry);
						}
						else {
							struct svr_entry *newentry = malloc(sizeof(struct svr_entry));
							newentry->fd = uncat_currentry->fd;
							snprintf(newentry->topic, MAX, "%s", topic);
							newentry->port = port;
							newentry->ip_addr = uncat_currentry->ip_addr;
							numServers++;

							LIST_INSERT_HEAD(&svr_list, newentry, svr_entries);
							LIST_REMOVE(uncat_currentry, uncat_entries);
							free(uncat_currentry);
						}
					}
				}
				uncat_currentry = uncat_e2;
			}
		}
	}
}

void sighandler(int signo) {
	printf("\nCaught signal: %d\n", signo);
	exit(0);
}
