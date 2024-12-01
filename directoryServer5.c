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
}
