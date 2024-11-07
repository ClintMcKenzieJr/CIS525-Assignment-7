#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

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

	// Request servers, wait to read, then wait for input, then write and wait to read
	// Request server list
	snprintf(s, MAX, "cl");
	write(sockfd, s, MAX);

	// Read server list
	if ((nread = read(sockfd, s, MAX)) < 0) {
		perror("Error reading from directory");
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

	write(sockfd, s, MAX);

	// Read server connection info
	if ((nread = read(sockfd, s, MAX)) < 0) {
		printf("Error reading from directory\n");
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
		close(sockfd);
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
					write(sockfd, s, MAX);
				} else {
					printf("Error reading or parsing user input\n");
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				if ((nread = read(sockfd, s, MAX)) < 0) {
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
	close(sockfd);
}
