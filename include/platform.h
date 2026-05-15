#pragma once

/*
 * Cross-platform networking helpers.
 *
 * - On Windows/MSVC use Winsock2.
 * - On POSIX use the usual sys/socket APIs.
 */

#include <stdint.h>

#ifdef _WIN32
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif

  /* winsock2.h must be included before windows.h */
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>

  typedef SOCKET socket_t;
  #define SOCKET_INVALID INVALID_SOCKET
  static inline int socket_valid(socket_t s) { return s != INVALID_SOCKET; }
  static inline int socket_close(socket_t s) { return closesocket(s); }
  static inline int socket_last_error(void) { return WSAGetLastError(); }

#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <sys/select.h>
  #include <unistd.h>
  #include <errno.h>

  typedef int socket_t;
  #define SOCKET_INVALID (-1)
  static inline int socket_valid(socket_t s) { return s >= 0; }
  static inline int socket_close(socket_t s) { return close(s); }
  static inline int socket_last_error(void) { return errno; }
#endif
