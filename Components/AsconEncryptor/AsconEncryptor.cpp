#include "Components/AsconEncryptor/AsconEncryptor.hpp"
#include <cstring> // for std::strlen
#include <stdexcept>
#include <vector>
#include <cstdio>

// -------------------------------
// ASCON HEADERS (C library)
// -------------------------------
extern "C" {
    #include "crypto_aead.h"  // crypto_aead_encrypt, crypto_aead_decrypt
    #include "api.h"          // CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, etc.
}

// A fixed 16-byte key for demonstration purposes
static const unsigned char KEY[CRYPTO_KEYBYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// A fixed 16-byte nonce (IV) for demonstration purposes
static const unsigned char NONCE[CRYPTO_NPUBBYTES] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

namespace Components {

  // ----------------------------------------------------------------------
  // Construction/Destruction
  // ----------------------------------------------------------------------

  AsconEncryptor::AsconEncryptor(const char* const compName)
    : AsconEncryptorComponentBase(compName),
      m_encCount(0),
      m_decCount(0),
      m_encTimeUs(0),
      m_decTimeUs(0)
  {
  }

  AsconEncryptor::~AsconEncryptor() {
  }

  // ----------------------------------------------------------------------
  // Utility: Convert bytes -> hex
  // ----------------------------------------------------------------------
  
  std::string AsconEncryptor::bytesToHex(const std::vector<uint8_t>& bytes) const {
      std::string hexStr;
      hexStr.reserve(bytes.size() * 2);
      for (auto b : bytes) {
          char buf[3];
          std::snprintf(buf, sizeof(buf), "%02X", b);
          hexStr += buf;
      }
      return hexStr;
  }

  // ----------------------------------------------------------------------
  // Utility: Convert hex -> bytes
  // ----------------------------------------------------------------------

  std::vector<uint8_t> AsconEncryptor::hexToBytes(const std::string& hexStr) const {
      if (hexStr.size() % 2 != 0) {
          throw std::runtime_error("hexToBytes: input length not even");
      }
      std::vector<uint8_t> result;
      result.reserve(hexStr.size() / 2);

      auto hexVal = [](char c) -> uint8_t {
          if (c >= '0' && c <= '9') return c - '0';
          c = std::tolower(static_cast<unsigned char>(c));
          if (c >= 'a' && c <= 'f') return c - 'a' + 10;
          throw std::runtime_error("hexToBytes: invalid hex char");
      };

      for (size_t i = 0; i < hexStr.size(); i += 2) {
          uint8_t high = hexVal(hexStr[i]);
          uint8_t low  = hexVal(hexStr[i + 1]);
          result.push_back((high << 4) | low);
      }
      return result;
  }

  // ----------------------------------------------------------------------
  // Encrypt
  // ----------------------------------------------------------------------

  void AsconEncryptor::Encrypt_cmdHandler(
      FwOpcodeType opCode,
      U32 cmdSeq,
      const Fw::CmdStringArg& data
  ) {
      // 1) Convert ASCII input -> raw bytes    
      const char* plaintextStr = data.toChar();
      size_t plaintext_len = std::strlen(plaintextStr);

      // DEBUG LOG ADDED (plaintext length)
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Encrypt: plaintext length: %zu", plaintext_len
          );
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      std::vector<uint8_t> plaintext(
          reinterpret_cast<const uint8_t*>(plaintextStr),
          reinterpret_cast<const uint8_t*>(plaintextStr) + plaintext_len
      );

      // 2) Prepare output buffer for ciphertext + auth tag
      std::vector<unsigned char> ciphertext(plaintext.size() + CRYPTO_ABYTES);

      // Benchmarking: Start timing
      Fw::Time start = this->getTime();
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Encrypt start: %u sec, %u usec", start.getSeconds(), start.getUSeconds());
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      // 3) Perform Ascon AEAD encryption      
      unsigned long long cLen = 0;
      int ret = crypto_aead_encrypt(
          ciphertext.data(), &cLen,
          plaintext.data(), static_cast<unsigned long long>(plaintext.size()),
          nullptr, 0,
          nullptr,
          NONCE,
          KEY
      );

      // Benchmarking: End timing
      Fw::Time end = this->getTime();
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Encrypt end: %u sec, %u usec", end.getSeconds(), end.getUSeconds());
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      if (ret != 0) {
          this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
          return;
      }

      // Benchmarking: Calculate and log total time
      U32 startUs = start.getSeconds() * 1000000 + start.getUSeconds();
      U32 endUs = end.getSeconds() * 1000000 + end.getUSeconds();
      m_encTimeUs = (endUs > startUs) ? (endUs - startUs) : 0;
      this->tlmWrite_EncryptTimeUs(m_encTimeUs);
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Encrypt completed in %u usec", m_encTimeUs);
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      ciphertext.resize(cLen);

      // DEBUG LOG ADDED (ciphertext length)      
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Encrypt: ciphertext length: %llu", cLen);
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      // 4) Convert ciphertext to hex for logging      
      std::string cipherHex = this->bytesToHex(std::vector<uint8_t>(
          ciphertext.begin(), ciphertext.end()
      ));

      // 5) Log event      
      Fw::LogStringArg cipherLog(cipherHex.c_str());
      this->log_ACTIVITY_HI_EncryptionSuccess(cipherLog);

      // 6) Telemetry increment      
      m_encCount++;
      this->tlmWrite_EncryptionCount(m_encCount);

      // 7) Respond      
      this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
  }

  // ----------------------------------------------------------------------
  // Decrypt
  // ----------------------------------------------------------------------  
  void AsconEncryptor::Decrypt_cmdHandler(
      FwOpcodeType opCode,
      U32 cmdSeq,
      const Fw::CmdStringArg& data
  ) {
      // 1) Log the raw command input
      {
          char dbgBuf[256];
          const char* rawData = data.toChar();
          size_t len = std::strlen(rawData);
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "Decrypt: raw input length=%zu, data='%.128s'",
              len, rawData);
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_HI_DebugLog(dbgArg);
      }

      // 2) Convert the input to std::string, check length
      std::string cipherHex = data.toChar();
      if (cipherHex.size() > 1024) {
          Fw::LogStringArg dbgArg("Input exceeds 1024 chars");
          this->log_ACTIVITY_HI_DebugLog(dbgArg);
          this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::VALIDATION_ERROR);
          return;
      }

      {
          char dbgBuf[128];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "Hex input length: %zu", cipherHex.size());
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_HI_DebugLog(dbgArg);
      }

      // 3) Attempt to parse hex -> bytes
      std::vector<uint8_t> cipherBytes;
      try {
          cipherBytes = this->hexToBytes(cipherHex);
      } catch (const std::exception& e) {
          {
              char dbgBuf[256];
              std::snprintf(dbgBuf, sizeof(dbgBuf),
                  "hexToBytes() failed: %s", e.what());
              Fw::LogStringArg dbgArg(dbgBuf);
              this->log_ACTIVITY_HI_DebugLog(dbgArg);
          }
          this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::VALIDATION_ERROR);
          return;
      }

      {
          // Log how many cipher bytes we got  
          char dbgBuf[128];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "cipherBytes length after parse: %zu", cipherBytes.size());
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_HI_DebugLog(dbgArg);
      }

      // 4) Prepare plaintext buffer
      std::vector<unsigned char> plaintext(cipherBytes.size());
      unsigned long long pLen = 0;

      // Benchmarking: Start timing
      Fw::Time start = this->getTime();
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Decrypt start: %u sec, %u usec", start.getSeconds(), start.getUSeconds());
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      // 5) Call Ascon decrypt
      int ret = crypto_aead_decrypt(
          plaintext.data(), &pLen,
          nullptr,
          cipherBytes.data(), (unsigned long long)cipherBytes.size(),
          nullptr, 0,
          NONCE,
          KEY
      );

      // Benchmarking: End timing
      Fw::Time end = this->getTime();
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Decrypt end: %u sec, %u usec", end.getSeconds(), end.getUSeconds());
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbg);
      }

      if (ret != 0) {
          // Auth failed or bad ciphertext => log debug event
          {
              char dbgBuf[100];
              std::snprintf(dbgBuf, sizeof(dbgBuf),
                  "Ascon decryption failed (ret=%d). Possibly incomplete or tampered ciphertext.",
                  ret);
              Fw::LogStringArg dbgArg(dbgBuf);
              this->log_ACTIVITY_HI_DebugLog(dbgArg);
          }
          this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
          return;
      }

      // Benchmarking: Calculate and log total time
      U32 startUs = start.getSeconds() * 1000000 + start.getUSeconds();
      U32 endUs = end.getSeconds() * 1000000 + end.getUSeconds();
      m_decTimeUs = (endUs > startUs) ? (endUs - startUs) : 0;
      this->tlmWrite_DecryptTimeUs(m_decTimeUs);
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Decrypt completed in %u usec", m_decTimeUs);
          Fw::LogStringArg dbgArg(debugBuf);
          this->log_ACTIVITY_HI_DebugLog(dbgArg);
      }

      // 6) Resize plaintext to actual length pLen
      plaintext.resize(pLen);

      // 7) Log the final plaintext length
      {
          char dbgBuf[128];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "Decryption success. Plaintext length: %llu", pLen);
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_HI_DebugLog(dbgArg);
      }

      // 8) Convert plaintext to ASCII for logging
      std::string plainAscii(
          reinterpret_cast<const char*>(plaintext.data()),
          reinterpret_cast<const char*>(plaintext.data() + plaintext.size())
      );

      // 9) Standard success event
      Fw::LogStringArg plainLog(plainAscii.c_str());
      this->log_ACTIVITY_HI_DecryptionSuccess(plainLog);

      // 10) Telemetry
      m_decCount++;
      this->tlmWrite_DecryptionCount(m_decCount);

      // 11) Command response OK
      this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
  }

  void AsconEncryptor::Benchmark_cmdHandler(
    FwOpcodeType opCode,
    U32 cmdSeq,
    U32 length,
    U32 runs
) {
    FILE* logFile = fopen("benchmark.csv", "a");
    if (!logFile) {
        this->log_ACTIVITY_HI_DebugLog(Fw::LogStringArg("Failed to open benchmark.csv"));
        this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
        return;
    }
    fseek(logFile, 0, SEEK_END);
    if (ftell(logFile) == 0) {
        fprintf(logFile, "Length,EncryptTimeUs,DecryptTimeUs\n");
    }

    std::vector<uint8_t> plaintext(length, 'A');
    std::vector<unsigned char> ciphertext(length + CRYPTO_ABYTES);
    std::vector<unsigned char> decrypted(length);

    for (U32 i = 0; i < runs; i++) {
        Fw::Time encStart = this->getTime();
        unsigned long long cLen = 0;
        int encRet = crypto_aead_encrypt(
            ciphertext.data(), &cLen,
            plaintext.data(), length,
            nullptr, 0,
            nullptr,
            NONCE,
            KEY
        );
        Fw::Time encEnd = this->getTime();

        if (encRet != 0) {
            this->log_ACTIVITY_HI_DebugLog(Fw::LogStringArg("Benchmark: Encrypt failed"));
            fclose(logFile);
            this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
            return;
        }

        U32 encTimeUs = (encEnd.getSeconds() * 1000000 + encEnd.getUSeconds()) -
                       (encStart.getSeconds() * 1000000 + encStart.getUSeconds());

        Fw::Time decStart = this->getTime();
        unsigned long long pLen = 0;
        int decRet = crypto_aead_decrypt(
            decrypted.data(), &pLen,
            nullptr,
            ciphertext.data(), cLen,
            nullptr, 0,
            NONCE,
            KEY
        );
        Fw::Time decEnd = this->getTime();

        if (decRet != 0) {
            this->log_ACTIVITY_HI_DebugLog(Fw::LogStringArg("Benchmark: Decrypt failed"));
            fclose(logFile);
            this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
            return;
        }

        U32 decTimeUs = (decEnd.getSeconds() * 1000000 + decEnd.getUSeconds()) -
                       (decStart.getSeconds() * 1000000 + decStart.getUSeconds());

        fprintf(logFile, "%u,%u,%u\n", length, encTimeUs, decTimeUs);
    }

    fclose(logFile);
    this->log_ACTIVITY_HI_DebugLog(Fw::LogStringArg("Benchmark completed"));
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
}
  
} // namespace Components
