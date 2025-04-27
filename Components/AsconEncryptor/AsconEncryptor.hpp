#ifndef Components_AsconEncryptor_HPP
#define Components_AsconEncryptor_HPP

#include "Components/AsconEncryptor/AsconEncryptorComponentAc.hpp"
#include <vector>
#include <string>

// ASCON HEADERS (C library) - Moved here to ensure CRYPTO_KEYBYTES is defined
extern "C" {
    #include "crypto_aead.h"  // crypto_aead_encrypt, crypto_aead_decrypt
    #include "api.h"          // CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, etc.
}

namespace Components {

  class AsconEncryptor : public AsconEncryptorComponentBase {

    public:
      // ----------------------------------------------------------------------
      // Construction/Destruction
      // ----------------------------------------------------------------------
      AsconEncryptor(const char* const compName);
      ~AsconEncryptor();

    PRIVATE:
      // ----------------------------------------------------------------------
      // Handler implementations for commands (matching .fpp)
      // ----------------------------------------------------------------------
      void Encrypt_cmdHandler(
          FwOpcodeType opCode,
          U32 cmdSeq,
          const Fw::CmdStringArg& data,
          U8 person,
          U16 portnumber
      ) override;

      void Decrypt_cmdHandler(
          FwOpcodeType opCode,
          U32 cmdSeq,
          const Fw::CmdStringArg& data
      ) override;

      void Benchmark_cmdHandler(
        FwOpcodeType opCode,
        U32 cmdSeq,
        U32 length,
        U32 runs
      );  // New benchmark handler

      // ----------------------------------------------------------------------
      // Utility Methods
      // ----------------------------------------------------------------------
      std::string bytesToHex(const std::vector<uint8_t>& bytes) const;
      std::vector<uint8_t> hexToBytes(const std::string& hexStr) const;

      // ----------------------------------------------------------------------
      // New port handlers from the patch
      // ----------------------------------------------------------------------
      void nonceOut_out(NATIVE_INT_TYPE portNum, Fw::Buffer& nonce);
      void cipherOut_out(NATIVE_INT_TYPE portNum, Fw::Buffer& cipher);

    private:
      // ----------------------------------------------------------------------
      // Local variables that track encryption/decryption counts, Timing Results
      // ----------------------------------------------------------------------
      U32 m_encCount;
      U32 m_decCount;
      U32 m_encTimeUs;  // Encryption time in microseconds
      U32 m_decTimeUs;  // Decryption time in microseconds
      bool keyLoaded;
      // ----------------------------------------------------------------------
      // New private member from the patch
      // ----------------------------------------------------------------------
      U8 sharedKey[CRYPTO_KEYBYTES];

      // ----------------------------------------------------------------------
      // New method from the patch
      // ----------------------------------------------------------------------
      void loadSharedKey();
  };

} // end namespace Components

#endif