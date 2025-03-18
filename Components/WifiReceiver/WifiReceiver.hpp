#ifndef Components_WifiReceiver_HPP
#define Components_WifiReceiver_HPP

#include "Components/WifiReceiver/WifiReceiverComponentAc.hpp"

namespace Components {

  class WifiReceiver : public WifiReceiverComponentBase {
    public:
      WifiReceiver(const char* compName);
      ~WifiReceiver();

    PRIVATE:
      // Invoked by the rate group at a configured interval
      void run_handler(NATIVE_INT_TYPE portNum, NATIVE_UINT_TYPE context) override;

      // Minimal required command
      void TODO_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) override;

    private:
      int m_sockfd;

      // Hard-coded KEY and NONCE. Must match the other side's encryption.
      static const unsigned char KEY[16];
      static const unsigned char NONCE[16];
  };

} // namespace Components

#endif
