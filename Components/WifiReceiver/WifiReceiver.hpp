#ifndef Components_WifiReceiver_HPP
#define Components_WifiReceiver_HPP

#include "Components/WifiReceiver/WifiReceiverComponentAc.hpp"

namespace Components {

  extern "C" {
    #include "crypto_aead.h"  // crypto_aead_encrypt, crypto_aead_decrypt
    #include "api.h"          // CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, etc.
}
  class WifiReceiver : public WifiReceiverComponentBase {
    public:
      WifiReceiver(const char* compName);
      ~WifiReceiver();

    PRIVATE:
      // Invoked by the rate group at a configured interval
      void run_handler(NATIVE_INT_TYPE portNum, NATIVE_UINT_TYPE context) override;

      // Minimal required command
      void TODO_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) override;

      // Load the shared key from file
      void loadSharedKey();

    private:
      int m_sockfd;
      U8 sharedKey[CRYPTO_KEYBYTES];  // Shared key for decryption
      U32 m_rxCount;  // Track received messages for telemetry
  };

} // namespace Components

#endif