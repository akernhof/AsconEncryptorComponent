#include "Components/WifiReceiver/WifiReceiver.hpp"

// BSD socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>  // for std::min

// ASCON library headers
extern "C" {
  #include "crypto_aead.h"
  #include "api.h"
}

// Matching the same KEY and NONCE as your AsconEncryptor
const unsigned char Components::WifiReceiver::KEY[16] = {
  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B,
  0x0C, 0x0D, 0x0E, 0x0F
};

const unsigned char Components::WifiReceiver::NONCE[16] = {
  0xA0, 0xA1, 0xA2, 0xA3,
  0xA4, 0xA5, 0xA6, 0xA7,
  0xA8, 0xA9, 0xAA, 0xAB,
  0xAC, 0xAD, 0xAE, 0xAF
};

namespace Components {

  WifiReceiver::WifiReceiver(const char* compName)
  : WifiReceiverComponentBase(compName),
    m_sockfd(-1)
  {
    // 1) Create a UDP socket
    this->m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (this->m_sockfd < 0) {
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "socket() failed: %s", strerror(errno));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));
      return;
    }

    // 2) Bind to a local port (6000 in this case) on 127.0.0.1
    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(6000);
    // Replace INADDR_ANY with 127.0.0.1 (Fix 3)
    inet_pton(AF_INET, "127.0.0.1", &localAddr.sin_addr); // Bind to localhost only

    if (bind(this->m_sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "bind() failed: %s", strerror(errno));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));
      close(this->m_sockfd);
      this->m_sockfd = -1;
      return;
    }

    // 3) Set the socket to non-blocking mode
    int flags = fcntl(this->m_sockfd, F_GETFL, 0);
    fcntl(this->m_sockfd, F_SETFL, flags | O_NONBLOCK);

    this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("WifiReceiver bound to UDP 127.0.0.1:6000 (non-blocking)"));
  }

  WifiReceiver::~WifiReceiver() {
    if (this->m_sockfd >= 0) {
      close(this->m_sockfd);
    }
  }

  void WifiReceiver::TODO_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) {
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
  }

  void WifiReceiver::run_handler(NATIVE_INT_TYPE portNum, NATIVE_UINT_TYPE context) {
    if (this->m_sockfd < 0) {
      return; // No socket available
    }

    uint8_t buffer[1024];
    sockaddr_in sender;
    socklen_t addrLen = sizeof(sender);

    // Non-blocking recvfrom call
    ssize_t recvSize = recvfrom(
      this->m_sockfd,
      buffer,
      sizeof(buffer),
      0,
      (struct sockaddr*)&sender,
      &addrLen
    );

    if (recvSize > 0) {
      // Fix 1: Filter Sender
      char senderIp[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &sender.sin_addr, senderIp, INET_ADDRSTRLEN);
      char dbgSender[128];
      snprintf(dbgSender, sizeof(dbgSender), "Received from %s:%d", senderIp, ntohs(sender.sin_port));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbgSender));
      if (strcmp(senderIp, "127.0.0.1") != 0) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Ignoring non-local packet"));
        return;
      }

      // Log received packet size
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "Received %ld bytes on UDP port 6000", (long)recvSize);
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));

      // Log a short hex dump (first 16 bytes)
      char hexDbg[128] = {0};
      size_t bytesToDump = std::min((size_t)recvSize, (size_t)16);
      for (size_t i = 0; i < bytesToDump; i++) {
        char byteStr[4];
        snprintf(byteStr, sizeof(byteStr), "%02X ", buffer[i]);
        strncat(hexDbg, byteStr, sizeof(hexDbg) - strlen(hexDbg) - 1);
      }
      char dbgHex[256];
      snprintf(dbgHex, sizeof(dbgHex), "Packet hex dump (first %zu bytes): %s", bytesToDump, hexDbg);
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbgHex));

      // Prepare a plaintext buffer with the same size as received ciphertext
      std::vector<unsigned char> plaintext(recvSize);
      unsigned long long pLen = 0;

      // Attempt to decrypt the raw bytes using Ascon
      int ret = crypto_aead_decrypt(
        plaintext.data(), &pLen,
        nullptr,
        buffer, (unsigned long long) recvSize,
        nullptr, 0,
        NONCE,
        KEY
      );

      if (ret != 0) {
        char dbgErr[128];
        snprintf(dbgErr, sizeof(dbgErr), "ASCON decryption failed (ret=%d)", ret);
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbgErr));
        return;
      }

      plaintext.resize((size_t)pLen);

      // Convert plaintext to a string for logging
      std::string plainAscii(
        reinterpret_cast<const char*>(plaintext.data()),
        plaintext.size()
      );

      // Log the decrypted plaintext
      this->log_ACTIVITY_HI_DecryptionSuccess(Fw::LogStringArg(plainAscii.c_str()));
    }
    else if (recvSize < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "recvfrom() error: %s", strerror(errno));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));
    }
    // If recvSize is -1 and errno is EAGAIN/EWOULDBLOCK, there is no data; do nothing.
  }

} // namespace Components