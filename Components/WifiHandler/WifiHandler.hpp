// WifiHandler.hpp

#ifndef Components_WifiHandler_HPP
#define Components_WifiHandler_HPP

#include "Components/WifiHandler/WifiHandlerComponentAc.hpp"

namespace Components {

  extern "C" {
    #include "crypto_aead.h"  // crypto_aead_encrypt, crypto_aead_decrypt
    #include "api.h"          // CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, etc.
}
  class WifiHandler : public WifiHandlerComponentBase {
    public:
      WifiHandler(const char* compName);
      ~WifiHandler();

    PRIVATE:
      // Handler for the input port we declared in .fpp
      void EncryptedDataIn_handler(NATIVE_INT_TYPE portNum, Fw::Buffer &fwBuffer) override;

      // Example command from .fpp
      void TODO_cmdHandler(FwOpcodeType opCode, U32 cmdSeq) override;
  };

} // namespace Components

#endif
