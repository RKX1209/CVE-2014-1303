#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void _start(void) {

  struct sockaddr_in addr;
  void *buf = (void *)0x607000;
  int server, client;
  int nr_socket = 41;
  int nr_bind = 49;
  int nr_listen = 50;
  int nr_accept = 43;
  int nr_read = 0;
  int nr_close = 3;
  int length;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(9023);
  addr.sin_zero[0] = 0;
  addr.sin_zero[1] = 0;
  addr.sin_zero[2] = 0;
  addr.sin_zero[3] = 0;
  addr.sin_zero[4] = 0;
  addr.sin_zero[5] = 0;

  server = syscall3 (nr_socket, AF_INET, SOCK_STREAM, 0);
  syscall3 (nr_bind, server, &addr, sizeof (addr));
  syscall2 (nr_listen, server, 10);
  client = syscall3 (nr_accept, server, 0, 0);

  while ((length = syscall3 (nr_read, client, buf, 4096)) > 0) {
    client += length;
  }
  syscall1 (nr_close, server);
  syscall1 (nr_close, client);
}
