// WifiHandler.cpp

#include "Components/WifiHandler/WifiHandler.hpp"

// Include Linux/BSD socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring> // for memset, etc.
#include <algorithm> // Added for std::min

namespace Components {

  WifiHandler::WifiHandler(const char* compName)
  : WifiHandlerComponentBase(compName)
  {
  }

  WifiHandler::~WifiHandler() {
    // Cleanup if needed
  }

  void WifiHandler::EncryptedDataIn_handler(
    NATIVE_INT_TYPE portNum,
    Fw::Buffer &fwBuffer
) {
    const U8* dataPtr = fwBuffer.getData();
    const U32 dataSize = fwBuffer.getSize();

    // Check minimum size (person + portnumber + nonce + smallest ciphertext)
    if (dataSize < sizeof(U8) + sizeof(U16) + CRYPTO_NPUBBYTES + CRYPTO_ABYTES) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Buffer too small"));
        return;
    }

    // Extract person and portnumber
    U8 person = dataPtr[0];
    U16 portnumber = (static_cast<U16>(dataPtr[1]) << 8) | dataPtr[2];

    // Calculate payload size (nonce + ciphertext only)
    const U32 payloadSize = dataSize - sizeof(U8) - sizeof(U16); // e.g., 36 bytes for "test"
    const U8* payload = dataPtr + sizeof(U8) + sizeof(U16); // Skip person and portnumber

    this->log_ACTIVITY_HI_ReceivedEncryptedData(dataSize);

    // Log full payload in hex (up to payloadSize bytes)
    char hexDbg[256] = {0}; // Increased size to fit full dump (36 bytes = 108 chars with spaces)
    for (U32 i = 0; i < payloadSize; i++) {
        snprintf(hexDbg + strlen(hexDbg), sizeof(hexDbg) - strlen(hexDbg), "%02X ", payload[i]);
    }
    char dbg[256]; // Increased to match
    snprintf(dbg, sizeof(dbg), "Sending %u bytes to person %u, port %u: %s", payloadSize, person, portnumber, hexDbg);
    this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));

    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Socket creation failed"));
        return;
    }

    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(portnumber);

    // Hardcoded IPs based on person
    const char* destIP;
    switch (person) {
        case 1: // UGV
            destIP = "0.0.0.0"; // Example IP for UGV
            break;
        case 2: // UAV
            destIP = "10.69.0.222"; // Example IP for UAV (ethernet right now for testing)
            break;
        case 3: // Fprime
            destIP = "127.0.0.1"; // Example IP for Fprime
            break;
        default:
            this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Invalid person value"));
            close(sockfd);
            return;
    }
    inet_pton(AF_INET, destIP, &destAddr.sin_addr);

    // Send only nonce + ciphertext (36 bytes)
    ssize_t sent = sendto(
        sockfd,
        payload,
        payloadSize,
        0,
        (struct sockaddr*)&destAddr,
        sizeof(destAddr)
    );

    if (sent < 0) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Send failed"));
    }

    close(sockfd);
}

  void WifiHandler::TODO_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) {
      // Example command no-op
      this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
  }

} // namespace Components