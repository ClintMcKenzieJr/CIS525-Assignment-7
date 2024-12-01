#include "common.h"
#include "inet.h"
#include <asm-generic/errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>

// Define if you DO NOT want TLS mode
//
#define NON_TLS_MODE

// Kind of client
typedef enum {
  CON_SERVER,
  CON_CLIENT,
  CON_NONE,
} client_kind_t;

typedef struct {
  int fd;
  client_kind_t kind;

  char* topic;
  size_t topic_len;
  struct sockaddr_in addr_info;

  // SERVER -> CLIENT
  char *tx;
  size_t tx_len;
  size_t tx_cap;

  // SERVER <- CLIENT
  char *rx;
  size_t rx_len;
  size_t rx_cap;

  // If this client should be removed from the list
  int disconnect;
} client_t;

// Verifies the integrity of the client stucture. These are common invariants
// that functions expect to be held.
//
// This is also a saftey measure, even though we don't care to 'check' our
// integrity for any important action (aka like disconnecting, info, etc...)
// its still important to ensure that its held.
#define VERIFY_CLIENT(client)                                                  \
  do {                                                                         \
    assert(client);                                                            \
    assert(client->fd);                                                        \
    assert(client->rx);                                                        \
    assert(client->tx);                                                        \
  } while (0);

// Create a new 'empty' client structure.
client_t new_client(void) {
  client_t client = {.fd = -1,
                     .kind = CON_NONE,

                     .topic = 0,
                     .topic_len = 0,
                     .addr_info = { 0 },

                     // MAX + 1 ensures even if we fill the buffer, there will
                     // still be a '\0'!
                     .tx = calloc(MAX + 1, sizeof(char)),
                     .tx_len = 0,
                     .tx_cap = MAX,

                     // MAX + 1 ensures even if we fill the buffer, there will
                     // still be a '\0'!
                     .rx = calloc(MAX + 1, sizeof(char)),
                     .rx_len = 0,
                     .rx_cap = MAX,

                     .disconnect = 0};

  if (!client.tx) {
    fprintf(stderr, "Failed to init a new client, TX buffer ptr was invalid\n");
    exit(1);
  }

  if (!client.rx) {
    fprintf(stderr, "Failed to init a new client, RX buffer ptr was invalid\n");
    exit(1);
  }

  return client;
}

// Delete/Free all allocated buffers for a client.
//
// This function will also set all fields to zero.
void free_client(client_t *client) {
  if (!client) return;
  if (client->rx) free(client->rx);
  if (client->tx) free(client->tx);
  if (client->topic) free(client->topic);

  // This is a saftey thing, we cannot double free
  // pointers if we entirely forget what they were
  // after we free them!
  memset(client, 0, sizeof(client_t));
}

// Handle a disconnect for a client
void disconnect_client(client_t *client) {
  if (!client)
    return;

  // Client has already been marked for disconnect
  if (client->disconnect)
    return;

  client->disconnect = 1;
  client->rx_len = 0;
}

// Send data to client
//
// Expected Invariants:
//  - Client passed select
//  - Client is ready to TX
//  - Socket is set to NONBLOCK
void client_tx(client_t *client) {
  VERIFY_CLIENT(client);

  // Nothing to send
  if (!client->tx_len)
    return;

  int tx_amount;

#ifdef NON_TLS_MODE
  tx_amount = write(client->fd, client->tx, client->tx_len);
#else
// ---------------- CONVERT ME TO TLS ----------------
#error "TLS mode has not been implemented yet!"
#endif

  if (tx_amount == EWOULDBLOCK)
    return;
  if (tx_amount < 0) {
    DEBUG_MSG("Failed to write to client, disconnecting them!\n");
    disconnect_client(client);
    return;
  }

  // Shift all bytes down
  memmove(client->tx, client->tx + tx_amount, client->tx_len - tx_amount);
  client->tx_len -= tx_amount;
  client->tx[client->tx_len] = 0;
}

// Get data from client
//
// Expected Invariants:
//  - Client passed select
//  - Client is ready to RX
//  - Socket is set to NONBLOCK
void client_rx(client_t *client) {
  VERIFY_CLIENT(client);

  // If we are in disconnected mode, we don't want to recv
  if (client->disconnect)
    return;

  // I don't feel the need to expand the buffers, so if the
  // client has filled their RX buffer we know we should
  // disconnect them!
  if (client->rx_len >= client->rx_cap) {
    DEBUG_MSG("Did not expect client to overfill their RX buffer, disconnecting them!\n");
    disconnect_client(client);
    return;
  }

  int rx_amount;
#ifdef NON_TLS_MODE
  rx_amount = read(client->fd, client->rx + client->rx_len,
                   client->rx_cap - client->rx_len);
#else
// ---------------- CONVERT ME TO TLS ----------------
#error "TLS mode has not been implemented yet!"
#endif

  if (rx_amount == EWOULDBLOCK) return;
  if (rx_amount <= 0) {
    DEBUG_MSG("Failed to read from client, disconnecting them!\n");
    disconnect_client(client);
    return;
  }

  client->rx_len += rx_amount;
}

client_t* find_server_with_topic(client_t* clients, size_t clients_len, char* topic, size_t topic_len) {
  assert(clients);
  assert(clients_len);

  for (int i = 0; i < clients_len; i++) {
    client_t* client = &clients[i];

    // Not a valid server
    if (client->kind != CON_SERVER) continue;
    if (client->disconnect) continue;
    if (!client->topic_len || !client->topic) continue;

    // Not the server we are looking for
    if (client->topic_len != topic_len && 
        strncmp(client->topic, topic, client->topic_len) != 0) continue;

    return client;
  }

  return NULL;
}

// Parse and process the client's message. 
//
// # Protocol
// 
// ## Server Side
//  1. THEM -> US                      : Server will connect to us
//  2. THEM("s{TOPIC}; {PORT}\0")      : Server will send its topic and port to us
//                                     :  - TOPIC is limited to `MAXTOPICLEN` of chars
//                                     :  - TOPIC cannot contain ',' or ';'
//                                     :  - PORT is an `uint16_t`
//  3. THEM -- US                      : Server doesn't disconnect, but keeps connection alive
//  4. THEM -X US                      : Server died and needs to be removed 
//
// ## Client Side
//  1. THEM -> US                      : Client will connect to us
//  2. THEM("cl")                      : Client will ask for all servers
//  3. US("{{TOPIC_N}\n*}")            : We send the client all servers
//  4. THEM("cl{TOPIC}")               : Client will ask for a server's IP and PORT
//  5. US("{TOPIC_IP};{TOPIC_PORT}")   : We will send the client the TOPIC's server IP and PORT
//  6. THEM -X US                      : Client will disconnect
//
void parse_client_msg(client_t* clients, size_t clients_len, client_t* client) {
  VERIFY_CLIENT(client);
  assert(clients);
  assert(clients_len);

  char* topic;
  uint16_t port;

  // If we have nothing to read, we just skip the whole process
  if (!client->rx) return;

  // Client Protocol : "Topic's Info Request" (Step 4)
  if (sscanf(client->rx, "cr%[^\n]", topic) == 1 && client->kind == CON_CLIENT) {

    int topic_len;
    if ((topic_len = strnlen(topic, MAXTOPICLEN + 2)) > MAXTOPICLEN) {
      // Oversized topic request
      disconnect_client(client);
      return;
    }

    client_t* topic_server = find_server_with_topic(clients, clients_len, topic, topic_len);

    // That topic doesn't exist
    if (!topic_server) {
      disconnect_client(client);
      return;
    }

    // Topic does exist
    uint32_t ip = topic_server->addr_info.sin_addr.s_addr;
    uint16_t port = topic_server->addr_info.sin_port;

    // -- Step 5 : Write "{TOPIC_IP};{TOPIC_PORT}" to client
    client->tx_len += snprintf(client->tx + client->tx_len, client->tx_cap - client->tx_len, 
                               "%u;%u", ip, port);

    // Reset client RX because we got a valid command
    memset(client->rx, 0, client->rx_len);
    client->rx_len = 0;
    
    return;
  }

  // Client Protocol : "Request all Topics" (Step 2)
  if (strncmp(client->rx, "cr", MAX) == 0 && client->kind == CON_NONE) {
    client->kind = CON_CLIENT;

    for (int i = 0; i < clients_len; i++) {
      client_t* topic_server  = &clients[i];

      // Not a valid server
      if (client->kind != CON_SERVER) continue;
      if (client->disconnect) continue;
      if (!client->topic_len || !client->topic) continue;

      client->tx_len += snprintf(
                                 client->tx + client->tx_len, 
                                 client->tx_cap - client->tx_len, 
                                 "%s", topic_server->topic);
    }

    // Reset client RX because we got a valid command
    memset(client->rx, 0, client->rx_len);
    client->rx_len = 0;    

    return;
  }

  // Server Protocol : "Send Topic Info" (Step 2)
  if (sscanf(client->rx, "s%[^;]; %hu", topic, &port) == 2 && client->kind == CON_NONE) {
    client->kind = CON_SERVER;

    int topic_len;
    if ((topic_len = strnlen(topic, MAXTOPICLEN + 2)) > MAXTOPICLEN) {
      // Oversized topic request
      disconnect_client(client);
      return;
    }

    client_t* topic_server = find_server_with_topic(clients, clients_len, topic, topic_len);

    // If we find a topic server with the same name, we disconnect the new one
    if (topic_server) {
      disconnect_client(client);
      return;
    }

    // Create a new Topic memory region
    client->topic = calloc(topic_len + 1, sizeof(char));
    assert(client->topic);

    // Write topic string into topic field
    client->topic_len = snprintf(client->topic, topic_len + 1, "%s", topic);

    // Reassign port
    client->addr_info.sin_port = port;

    // Reset client RX because we got a valid command
    memset(client->rx, 0, client->rx_len);
    client->rx_len = 0;    

    return;
  }

  // If the first char isn't a valid one, we disconnect them
  if (client->rx[0] != 's' && client->rx[0] != 'c') {
    disconnect_client(client);
    return;
  }

  // Otherwise we are still waiting for a valid command...
  DEBUG_MSG("Still waiting for valid msg: ");
  DEBUG_DIRTY_MSG(client->rx, client->rx_len);
}

int fill_fdset(client_t *clients, size_t clients_len, int serverfd, fd_set *read_set, fd_set *write_set) {
  assert(clients);
  assert(clients_len);
  assert(read_set);
  assert(write_set);

  FD_ZERO(read_set);
  FD_ZERO(write_set);

  int max_fd = serverfd;
  FD_SET(serverfd, read_set);

  for (int i = 0; i < clients_len; i++) {
    client_t *client = &clients[i];

    if (!client)
      continue;
    if (client->fd > max_fd)
      max_fd = client->fd;

    FD_SET(client->fd, read_set);
    FD_SET(client->fd, write_set);
  }

  return max_fd;
}

int main(int argc, char** argv) {
  // 1. Create communication endpoint
  int serverfd;
  if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("chatServer -- can't open stream socket");
    return 1;
  }

  /* 2.
   * Add SO_REAUSEADDR option to prevent address in use errors (modified from:
   * "Hands-On Network Programming with C" Van Winkle, 2019.
   * https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml
   */
  int true = 1;
  if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true,
                 sizeof(true)) < 0) {
    perror("chatServer -- can't set stream socket address reuse option");
    return 1;
  }

  /* 3. Bind socket to local address */
  struct sockaddr_in serv_addr;
  memset((char *)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(DIR_HOST_ADDR);
  serv_addr.sin_port = htons(DIR_TCP_PORT);

  if (bind(serverfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("chatServer -- can't bind local address");
    return 1;
  }

  // 4. Set max clients
  if (listen(serverfd, MAX_CLIENTS) < 0) {
    perror("chatServer -- can't set max clients");
    return 1;
  }

  fd_set readset;
  fd_set writeset;

  client_t *clients = NULL;
  size_t clients_len = 0;
  size_t clients_cap = 0;

  // 5. Start our main loop
  DEBUG_MSG("Starting mainloop!\n");
  for (;;) {
    int max_fd = fill_fdset(clients, clients_len, serverfd, &readset, &writeset);

    if (select(max_fd + 1, &readset, &writeset, NULL, NULL) < 0) {
      perror("chatServer -- can't select");
      return 1;
    }

    // Bind new client
    if (FD_ISSET(serverfd, &readset)) {
      DEBUG_MSG("New Client!!\n");
      struct sockaddr_in cli_addr;
      socklen_t clilen = sizeof(cli_addr);

      // Accept new socket
      int newsockfd;
      if ((newsockfd =
               accept(serverfd, (struct sockaddr *)&cli_addr, &clilen)) < 0) {
        perror("chatServer: accept error");
        exit(1);
      }

      // Set socket to non-blocking
      if (fcntl(newsockfd, F_SETFL, O_NONBLOCK) < 0) {
        perror("chatServer -- can't set socket to non-blocking...");
        return 1;
      }

      // Create the new client structure
      client_t client = new_client();
      client.fd = newsockfd;
      client.addr_info = cli_addr;

      // Need to create a new array
      if (!clients) {
        clients_cap = 2;
        clients = calloc(clients_cap, sizeof(client_t));

        assert(clients);
      }

      // Need to expand the array
      if (clients_len + 1 >= clients_cap) {
        clients_cap *= 2;
        clients = reallocarray(clients, clients_cap, sizeof(client_t));

        assert(clients);
      }

      // Put the client into the array
      clients[clients_len++] = client;
    }

    for (int i = 0; i < clients_len; i++) {
      client_t *client = &clients[i];

      if (!client)
        continue;

      if (FD_ISSET(client->fd, &readset)) {
        // We want to get anything the client might've sent us
        client_rx(client);

        // Then we process it each time, regardless if the msg
        // is finished
        parse_client_msg(clients, clients_len, client);
      }

      if (FD_ISSET(client->fd, &writeset)) {
        client_tx(client);
      }
    }

    // When we handle a client and its time for disconnect, we won't
    // remove it from the list. Since it can cause UB, so instead we
    // disconnect the client and set it's FD to `0`.
    //
    // Here we look though all the client's that have FDs of zero,
    // and actually remove them from the list.
    //
    // Since we are iter over the list at the same time as modifying
    // the list we need to be extra careful to ensure we don't RW to
    // undefined memory.
    //
    // NOTE:
    // This can be done in the main loop, but its much eaiser to
    // verify the soundness of the above loop without this. That is
    // why it is moved to another loop.
    for (int i = 0; i < clients_len; i++) {
      const client_t *client = &clients[i];

      if (!client)
        continue;
      if (client->fd)
        continue;

      DEBUG_MSG("Removing client at index='%d' from the list!\n", i);

      // Pulled from heaplist from previous assignments
      //
      // # Steps:
      // 
      // So, we have an array like this:
      //    [ X , X , 4 , 3 , 2 , 1]
      // 
      // Where 'X' is an empty element. So, this array will have
      // a length of 4, and a capacity of 6. If we want to remove
      // element '2' from the array we need to shift '3' and '4' 
      // down one element. 
      //
      // 'dest' is the source element of the move (aka the '2' from
      // our example above) and 'src' is the element above it. 
      // 
      // We must also calculate the exact number of _bytes_ needed
      // for the copy, and the result is stored in 'count'.
      //
      // # Graphic Explaining the process:
      //
      //   [ X , X , 4 , 3 , 2 , 1]  | : Starting array
      //           [ 4 , 3 ]         | : The elements we want to move
      //               [ 4 , 3 ]     | : Copied one element down
      //   [ X , X , X , 4 , 3 , 1 ] X : Final Array
      //
      size_t el_size = sizeof(client_t);
      client_t* src = clients + (el_size * (i + 1));
      client_t* dest = clients + (el_size * i);

      size_t count = (clients_len - i - 1) * el_size;
      clients_len--;

      memmove(dest, src, count);
    }
  }
}
