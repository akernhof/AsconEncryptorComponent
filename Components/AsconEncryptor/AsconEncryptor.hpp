#ifndef Components_AsconEncryptor_HPP
#define Components_AsconEncryptor_HPP

#include "Components/AsconEncryptor/AsconEncryptorComponentAc.hpp"
#include "Components/AsconEncryptor/AsconEncryptorComponentAc.hpp"
#include <vector>
#include <string>

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
          const Fw::CmdStringArg& data
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
    private:
      // ----------------------------------------------------------------------
      // Local variables that track encryption/decryption counts, Timing Results
      // ----------------------------------------------------------------------
      U32 m_encCount;
      U32 m_decCount;
      U32 m_encTimeUs;  // Encryption time in microseconds
      U32 m_decTimeUs;  // Decryption time in microseconds
  };

} // end namespace Components

#endif
