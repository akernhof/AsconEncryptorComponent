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
#include <fstream>    // For file I/O

// ASCON library headers
extern "C" {
  #include "crypto_aead.h"
  #include "api.h"
}

namespace Components {

  WifiReceiver::WifiReceiver(const char* compName)
  : WifiReceiverComponentBase(compName),
    m_sockfd(-1),
    m_rxCount(0)
  {
    // Load the shared key
    this->loadSharedKey();

    // 1) Create a UDP socket
    this->m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (this->m_sockfd < 0) {
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "socket() failed: %s", strerror(errno));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));
      return;
    }

    // 2) Bind to a local port (6000) on 127.0.0.1
    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(6000);
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

  void WifiReceiver::loadSharedKey() {
    const char* keyFile = "/tmp/shared_key.bin";
    std::ifstream keyIn(keyFile, std::ios::in | std::ios::binary);

    if (!keyIn) {
      char debugBuf[128];
      std::snprintf(debugBuf, sizeof(debugBuf), "Failed to open shared key file at %s", keyFile);
      Fw::LogStringArg dbg(debugBuf);
      this->log_ACTIVITY_LO_DebugLog(dbg);
      memset(this->sharedKey, 0, CRYPTO_KEYBYTES);
      return;
    }

    keyIn.read(reinterpret_cast<char*>(this->sharedKey), CRYPTO_KEYBYTES);
    if (keyIn.gcount() != CRYPTO_KEYBYTES) {
      char debugBuf[128];
      std::snprintf(debugBuf, sizeof(debugBuf), "Shared key read incomplete: got %ld bytes", static_cast<long>(keyIn.gcount()));
      Fw::LogStringArg dbg(debugBuf);
      this->log_ACTIVITY_LO_DebugLog(dbg);
      memset(this->sharedKey, 0, CRYPTO_KEYBYTES);
    } else {
      char debugBuf[128];
      std::snprintf(debugBuf, sizeof(debugBuf), "Loaded shared key from %s", keyFile);
      Fw::LogStringArg dbg(debugBuf);
      this->log_ACTIVITY_LO_DebugLog(dbg);
    }

    keyIn.close();
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
      // Filter sender
      char senderIp[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &sender.sin_addr, senderIp, INET_ADDRSTRLEN);
      char dbgSender[128];
      snprintf(dbgSender, sizeof(dbgSender), "Received from %s:%d", senderIp, ntohs(sender.sin_port));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbgSender));
      if (strcmp(senderIp, "127.0.0.1") != 0) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Ignoring non-local packet"));
        return;
      }

      // Check minimum size (nonce + smallest possible ciphertext)
      if (recvSize < CRYPTO_NPUBBYTES + CRYPTO_ABYTES) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Packet too small"));
        return;
      }

      // Extract nonce and ciphertext
      const uint8_t* nonce = buffer;                          // First 16 bytes
      const uint8_t* ciphertext = buffer + CRYPTO_NPUBBYTES;  // Rest of the buffer
      size_t cipherSize = recvSize - CRYPTO_NPUBBYTES;

      // Log received packet size
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "Received %ld bytes (nonce: 16, cipher: %zu)", (long)recvSize, cipherSize);
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

      // Prepare a plaintext buffer
      std::vector<unsigned char> plaintext(cipherSize);
      unsigned long long pLen = 0;

      // Attempt to decrypt using the received nonce and shared key
      int ret = crypto_aead_decrypt(
        plaintext.data(), &pLen,
        nullptr,
        ciphertext, (unsigned long long)cipherSize,
        nullptr, 0,
        nonce,
        this->sharedKey
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

      // Update telemetry
      m_rxCount++;
      this->tlmWrite_RxCount(m_rxCount);
    }
    else if (recvSize < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "recvfrom() error: %s", strerror(errno));
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));
    }
    // If recvSize is -1 and errno is EAGAIN/EWOULDBLOCK, there is no data; do nothing.
  }

} // namespace Components