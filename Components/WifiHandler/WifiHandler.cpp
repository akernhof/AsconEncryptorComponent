// WifiHandler.cpp

#include "Components/WifiHandler/WifiHandler.hpp"

// Include Linux/BSD socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring> // for memset, etc.

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

      // 2) Example: open a UDP socket and send to 192.168.1.100:5000
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
