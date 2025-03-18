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
      // 1) Extract data pointer and size
      const U8* dataPtr = fwBuffer.getData();
      const U32 dataSize = fwBuffer.getSize();

      this->log_ACTIVITY_HI_ReceivedEncryptedData(dataSize);

      // Fix 4: Log Sent Data
      char hexDbg[128] = {0};
      for (U32 i = 0; i < std::min(dataSize, 16U); i++) {
        snprintf(hexDbg + strlen(hexDbg), sizeof(hexDbg) - strlen(hexDbg), "%02X ", dataPtr[i]);
      }
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "Sending hex: %s", hexDbg);
      this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg(dbg));

      // 2) Example: open a UDP socket and send to 127.0.0.1:6000
      int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
      if (sockfd < 0) {
          // Potentially log an event or handle error
          return;
      }

      struct sockaddr_in destAddr;
      memset(&destAddr, 0, sizeof(destAddr));
      destAddr.sin_family = AF_INET;
      destAddr.sin_port = htons(6000);
      inet_pton(AF_INET, "127.0.0.1", &destAddr.sin_addr);

      // 3) Send the data
      ssize_t sent = sendto(
          sockfd,
          dataPtr,
          dataSize,
          0,
          (struct sockaddr*)&destAddr,
          sizeof(destAddr)
      );

      if (sent < 0) {
          // Log an event or handle error
      }

      close(sockfd);
  }

  void WifiHandler::TODO_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) {
      // Example command no-op
      this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
  }

} // namespace Components