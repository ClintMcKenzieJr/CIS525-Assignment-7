#include "common.h"
#include "inet.h"
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct server_entry {
  int fd;
  char topic[MAXTOPICLEN];
  unsigned short port;
  unsigned long ip_addr;
  LIST_ENTRY(server_entry) servers;
} server_t;

typedef struct client_entry {
  int fd;
  char tx_buffer[MAX];
  LIST_ENTRY(client_entry) clients;
} client_t;

typedef struct uncat_entry {
  int fd;
  unsigned long ip_addr;
  LIST_ENTRY(uncat_entry) unknowns;
} unknown_t;

LIST_HEAD(svr_listhead, server_entry);
LIST_HEAD(cli_listhead, client_entry);
LIST_HEAD(uncat_listhead, uncat_entry);

void sighandler(int);

int main(int argc, char **argv) {
  int repeat_name;
  char recv_str[MAX], outmsg[MAX], tempmsg[MAX], topic[MAXTOPICLEN];

  server_t *server_current_entry;
  client_t *client_current_entry, *client_next;

  struct uncat_entry *unknown_current_entry, *unknown_next;
  int n_servers = 0;

  struct svr_listhead server_ll;
  struct cli_listhead client_ll;
  struct uncat_listhead unknown_ll;

  LIST_INIT(&server_ll);
  LIST_INIT(&client_ll);
  LIST_INIT(&unknown_ll);

  signal(SIGINT, sighandler);

  /* Create communication endpoint */
  int server_fd;
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("directory: can't open stream socket");
    exit(1);
  }

  int true = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true)) < 0) {
    perror("directory: can't set stream socket address reuse option");
    exit(1);
  }

  struct sockaddr_in socket_info = {0};

  socket_info.sin_family = AF_INET;
  socket_info.sin_addr.s_addr = inet_addr(DIR_HOST_ADDR);
  socket_info.sin_port = htons(DIR_TCP_PORT);

  if (bind(server_fd, (struct sockaddr *)&socket_info, sizeof(socket_info)) < 0) {
    perror("directory: can't bind local address");
    exit(1);
  }

  if (listen(server_fd, MAX_SERVERS) < 0) {
    perror("directory: can't listen on socket");
    exit(1);
  }

  fd_set readset, writeset;

  for (;;) {
    FD_ZERO(&readset);
    FD_ZERO(&writeset);

    int maxsockfd = server_fd;

    // Checking listening socket
    FD_SET(server_fd, &readset);

    // Listening to all uncategorized connections
    LIST_FOREACH(unknown_current_entry, &unknown_ll, unknowns) {
      FD_SET(unknown_current_entry->fd, &readset);
      if (unknown_current_entry->fd > maxsockfd)
        maxsockfd = unknown_current_entry->fd;
    }

    // Checking all servers to see if they have disconnected
    LIST_FOREACH(server_current_entry, &server_ll, servers) {
      FD_SET(server_current_entry->fd, &readset);
      if (server_current_entry->fd > maxsockfd)
        maxsockfd = server_current_entry->fd;
    }

    // Checking all clients for messages
    LIST_FOREACH(client_current_entry, &client_ll, clients) {
      FD_SET(client_current_entry->fd, &readset);
      if (client_current_entry->fd > maxsockfd)
        maxsockfd = client_current_entry->fd;
    }

    // Write to all clients who have a message waiting
    LIST_FOREACH(client_current_entry, &client_ll, clients) {
      if (strncmp(client_current_entry->tx_buffer, "\0", MAX) == 0) {
        continue;
      }

      FD_SET(client_current_entry->fd, &writeset);
      if (client_current_entry->fd > maxsockfd)
        maxsockfd = client_current_entry->fd;
    }

    int select_count;
    if ((select_count =
             select((maxsockfd + 1), &readset, &writeset, NULL, NULL)) <= 0) {
      perror("directory: Failed to select");
      exit(1);
    }

    // Accept a new connection request
    if (FD_ISSET(server_fd, &readset)) {
      struct sockaddr_in client_info;

      socklen_t client_info_len = sizeof(client_info);
      int client_fd =
          accept(server_fd, (struct sockaddr *)&client_info, &client_info_len);

      if (client_fd < 0) {
        perror("server: failed to accept on socket");
        exit(1);
      } else {
        unknown_t *newentry = calloc(1, sizeof(struct uncat_entry));

        newentry->fd = client_fd;
        newentry->ip_addr = client_info.sin_addr.s_addr;

        LIST_INSERT_HEAD(&unknown_ll, newentry, unknowns);
      }
    }

    server_current_entry = LIST_FIRST(&server_ll);
    while (server_current_entry != NULL) {
      server_t* next_server_entry = LIST_NEXT(server_current_entry, servers);

      if (!FD_ISSET(server_current_entry->fd, &readset)) {
        // Check if the server connection has closed
        if (read(server_current_entry->fd, recv_str, MAX) <= 0) {
          // Handle server disconnect/shutdown
          n_servers--;
          close(server_current_entry->fd);
          LIST_REMOVE(server_current_entry, servers);
          free(server_current_entry);
        }
      }

      server_current_entry = next_server_entry;
    }

    client_current_entry = LIST_FIRST(&client_ll);
    while (client_current_entry != NULL) {
      client_next = LIST_NEXT(client_current_entry, clients);

      // If client sent a message
      if (FD_ISSET(client_current_entry->fd, &readset)) {
        // Read, determine type (if not starting with "cr" or asking for
        // nonexistent server or read=0, close)
        if (read(client_current_entry->fd, recv_str, MAX) <= 0) {
          close(client_current_entry->fd);
          LIST_REMOVE(client_current_entry, clients);
          free(client_current_entry);
        } else if (strncmp(recv_str, "cr", 2) == 0) {
          // This should always parse correctly, since it should be formatted
          // correctly on the client's end
          if (sscanf(recv_str, "cr%[^\n]", topic) != 1) {
            printf("Failed to parse server info\n");
            exit(1);
          }
          server_current_entry = LIST_FIRST(&server_ll);
          while (server_current_entry != NULL) {
            server_t* next_server_entry = LIST_NEXT(server_current_entry, servers);
            if (strncmp(topic, server_current_entry->topic, MAXTOPICLEN - 1) ==
                0) {
              snprintf(client_current_entry->tx_buffer, MAX, "%lu;%hu",
                       server_current_entry->ip_addr,
                       server_current_entry->port);
              next_server_entry = NULL;
            }
            server_current_entry = next_server_entry;
          }
          // Setting the message field will add the client to the write set next
          // time around Or, if the given topic doesn't exist, close the
          // connection without writing
          if (strncmp(client_current_entry->tx_buffer, "\0", MAX) == 0) {
            close(client_current_entry->fd);
            LIST_REMOVE(client_current_entry, clients);
            free(client_current_entry);
          }
        } else {
          // Unexpected client message (really shouldn't be possible)
          close(client_current_entry->fd);
          LIST_REMOVE(client_current_entry, clients);
          free(client_current_entry);
        }
      }
      // If client is ready to be sent a message
      else if (FD_ISSET(client_current_entry->fd, &writeset)) {
        write(client_current_entry->fd, client_current_entry->tx_buffer, MAX);
        memset(client_current_entry->tx_buffer, 0, MAX);
      }
      client_current_entry = client_next;
    }

    // for fd in uncat_list:
    unknown_current_entry = LIST_FIRST(&unknown_ll);
    while (unknown_current_entry != NULL) {
      unknown_next = LIST_NEXT(unknown_current_entry, unknowns);
      if (FD_ISSET(unknown_current_entry->fd, &readset)) {
        // Socket closed or invalid first message (first messages should always
        // be at least 2 chars long)
        if (read(unknown_current_entry->fd, recv_str, MAX) <= 0 || strnlen(recv_str, MAX) < 2) {
          close(unknown_current_entry->fd);

          LIST_REMOVE(unknown_current_entry, unknowns);
          free(unknown_current_entry);
        }

        // Determine type
        // A client's first message will always be "cl"
        if (strncmp(recv_str, "cl", 2) == 0) {
          client_t *newentry = calloc(1, sizeof(client_t));
          newentry->fd = unknown_current_entry->fd;

          memset(outmsg, '\0', MAX);
          memset(tempmsg, '\0', MAX);
          select_count = 1;
          server_current_entry = LIST_FIRST(&server_ll);
          while (server_current_entry != NULL) {
            server_t* next_server_entry = LIST_NEXT(server_current_entry, servers);
            // Checks if outmsg has enough space
            if ((strnlen(outmsg, MAX) + MAXTOPICLEN + 2 <= MAX) ||
                (select_count == 5 &&
                 strnlen(outmsg, MAX) + MAXTOPICLEN <= MAX)) {
              // strncat(outmsg, svr_currentry->topic, MAXTOPICLEN);
              snprintf(tempmsg, strnlen(outmsg, MAX) + MAXTOPICLEN, "%s%s",
                       outmsg, server_current_entry->topic);
              snprintf(outmsg, strnlen(outmsg, MAX) + MAXTOPICLEN, "%s",
                       tempmsg);
              if (select_count != n_servers)
                strncat(outmsg, ", ", 3);
            }

            server_current_entry = next_server_entry;
            select_count++;
          }
          snprintf(newentry->tx_buffer, MAX, "%s", outmsg);
          LIST_INSERT_HEAD(&client_ll, newentry, clients);
          LIST_REMOVE(unknown_current_entry, unknowns);
          free(unknown_current_entry);
        }
        // A server's first (and only) message will always start with 's'
        else if (strncmp(recv_str, "s", 1) == 0) {
          // This should always parse correctly, since it should be formatted
          // correctly on the server's end

          uint16_t port = 0;
          if (sscanf(recv_str, "s%[^;]; %hu", topic, &port) != 2) {
            printf("Failed to parse server info\n");
            exit(1);
          }

          repeat_name = 0;

          server_t* next_server_entry;
          LIST_FOREACH(next_server_entry, &server_ll, servers) {
            if (strncmp(topic, next_server_entry->topic, MAXTOPICLEN - 1) == 0) {
              repeat_name = 1;
            }
          }

          if (repeat_name || n_servers >= 5) {
            // Close the socket; the server will know to shut down
            close(unknown_current_entry->fd);
            LIST_REMOVE(unknown_current_entry, unknowns);
            free(unknown_current_entry);
          } else {
            server_t *newentry = calloc(1, sizeof(server_t));

            newentry->fd = unknown_current_entry->fd;
            snprintf(newentry->topic, MAX, "%s", topic);
            newentry->port = port;
            newentry->ip_addr = unknown_current_entry->ip_addr;
            n_servers++;

            LIST_INSERT_HEAD(&server_ll, newentry, servers);
            LIST_REMOVE(unknown_current_entry, unknowns);
            free(unknown_current_entry);
          }
        }
      }
      unknown_current_entry = unknown_next;
    }
  }
}

void sighandler(int signo) {
  printf("\nCaught signal: %d\n", signo);
  exit(0);
}
