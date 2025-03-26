#include "Components/AsconEncryptor/AsconEncryptor.hpp"
#include <cstring> // for std::strlen
#include <stdexcept>
#include <vector>
#include <cstdio>
#include <fstream> // For file I/O
#include <random>  // For random number generation
#include "Fw/Types/Assert.hpp"
#include "Fw/Logger/Logger.hpp"

// ASCON HEADERS (C library) - Already included in .hpp, but kept here for completeness
extern "C" {
    #include "crypto_aead.h"  // crypto_aead_encrypt, crypto_aead_decrypt
    #include "api.h"          // CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, etc.
}

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
    this->loadSharedKey(); // Load the shared key during construction
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
  // Load Shared Key
  // ----------------------------------------------------------------------
  void AsconEncryptor::loadSharedKey() {
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

  // ----------------------------------------------------------------------
  // Encrypt
  // ----------------------------------------------------------------------
  void AsconEncryptor::Encrypt_cmdHandler(
    FwOpcodeType opCode,
    U32 cmdSeq,
    const Fw::CmdStringArg& data,
    U8 person,      // New person parameter
    U16 portnumber  // Existing port parameter
) {
    // 1) Convert ASCII input -> raw bytes    
    const char* plaintextStr = data.toChar();
    size_t plaintext_len = std::strlen(plaintextStr);

    {
        char debugBuf[128];
        std::snprintf(debugBuf, sizeof(debugBuf), "Encrypt: plaintext length: %zu, person: %u, port: %u", plaintext_len, person, portnumber);
        Fw::LogStringArg dbg(debugBuf);
        this->log_ACTIVITY_LO_DebugLog(dbg);
    }

    std::vector<uint8_t> plaintext(
        reinterpret_cast<const uint8_t*>(plaintextStr),
        reinterpret_cast<const uint8_t*>(plaintextStr) + plaintext_len
    );

    // 2) Generate a random nonce
    U8* nonce = new U8[CRYPTO_NPUBBYTES];
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < CRYPTO_NPUBBYTES; ++i) {
        nonce[i] = static_cast<U8>(dis(gen));
    }

    // 3) Prepare output buffer for ciphertext + auth tag
    std::vector<unsigned char> ciphertext(plaintext.size() + CRYPTO_ABYTES);
    unsigned long long cLen = 0;

    // Benchmarking: Start timing
    Fw::Time start = this->getTime();
    {
        char debugBuf[128];
        std::snprintf(debugBuf, sizeof(debugBuf), "Encrypt start: %u sec, %u usec", start.getSeconds(), start.getUSeconds());
        Fw::LogStringArg dbg(debugBuf);
        this->log_ACTIVITY_LO_DebugLog(dbg);
    }

    // 4) Perform Ascon AEAD encryption
    int ret = crypto_aead_encrypt(
        ciphertext.data(), &cLen,
        plaintext.data(), static_cast<unsigned long long>(plaintext.size()),
        nullptr, 0,
        nullptr,
        nonce,
        this->sharedKey
    );

    // Benchmarking: End timing
    Fw::Time end = this->getTime();
    {
        char debugBuf[128];
        std::snprintf(debugBuf, sizeof(debugBuf), "Encrypt end: %u sec, %u usec", end.getSeconds(), end.getUSeconds());
        Fw::LogStringArg dbg(debugBuf);
        this->log_ACTIVITY_LO_DebugLog(dbg);
    }

    if (ret != 0) {
        char debugBuf[128];
        std::snprintf(debugBuf, sizeof(debugBuf), "[ASCON] Encryption failed");
        Fw::LogStringArg dbg(debugBuf);
        this->log_ACTIVITY_LO_DebugLog(dbg);
        delete[] nonce;
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
        std::snprintf(debugBuf, sizeof(debugBuf), "Encrypt completed in %u usec", m_encTimeUs);
        Fw::LogStringArg dbg(debugBuf);
        this->log_ACTIVITY_LO_DebugLog(dbg);
    }

    ciphertext.resize(cLen);

    // 5) Combine person, portnumber, nonce, and ciphertext into a single buffer
    const U32 totalSize = sizeof(U8) + sizeof(U16) + CRYPTO_NPUBBYTES + cLen; // 1 person + 2 port + 16 nonce + ciphertext
    U8* combinedData = new U8[totalSize];
    // Person (1 byte)
    combinedData[0] = person;
    // Portnumber (2 bytes)
    combinedData[1] = static_cast<U8>(portnumber >> 8); // High byte
    combinedData[2] = static_cast<U8>(portnumber & 0xFF); // Low byte
    // Nonce (16 bytes)
    memcpy(combinedData + sizeof(U8) + sizeof(U16), nonce, CRYPTO_NPUBBYTES);
    // Ciphertext
    memcpy(combinedData + sizeof(U8) + sizeof(U16) + CRYPTO_NPUBBYTES, ciphertext.data(), cLen);
    Fw::Buffer outBuffer(combinedData, totalSize); // e.g., 39 bytes for "test"

    delete[] nonce;

    // 6) Output via EncryptedDataOut
    if (this->isConnected_EncryptedDataOut_OutputPort(0)) {
        this->EncryptedDataOut_out(0, outBuffer);
    } else {
        delete[] combinedData;
    }

    // 7) Log transmission
    {
        char debugBuf[128];
        std::snprintf(debugBuf, sizeof(debugBuf), "[ASCON] Sent nonce + cipher. Total length: %u", totalSize);
        Fw::LogStringArg dbg(debugBuf);
        this->log_ACTIVITY_LO_DebugLog(dbg);
    }

    // 8) Log ciphertext
    std::string cipherHex = this->bytesToHex(std::vector<uint8_t>(ciphertext.begin(), ciphertext.end()));
    Fw::LogStringArg cipherLog(cipherHex.c_str());
    this->log_ACTIVITY_HI_EncryptionSuccess(cipherLog);

    // 9) Telemetry and response
    m_encCount++;
    this->tlmWrite_EncryptionCount(m_encCount);
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
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
      }

      // 2) Convert the input to std::string, check length
      std::string cipherHex = data.toChar();
      if (cipherHex.size() > 1024) {
          Fw::LogStringArg dbgArg("Input exceeds 1024 chars");
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
          this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::VALIDATION_ERROR);
          return;
      }

      {
          char dbgBuf[128];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "Hex input length: %zu", cipherHex.size());
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
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
              this->log_ACTIVITY_LO_DebugLog(dbgArg);
          }
          this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::VALIDATION_ERROR);
          return;
      }

      {
          char dbgBuf[128];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "cipherBytes length after parse: %zu", cipherBytes.size());
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
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
          this->log_ACTIVITY_LO_DebugLog(dbg);
      }

      // 5) Call Ascon decrypt - Note: Nonce is missing here!
      // Temporarily use a placeholder nonce (this needs to be fixed)
      U8 tempNonce[CRYPTO_NPUBBYTES] = {0}; // Placeholder; needs actual nonce
      int ret = crypto_aead_decrypt(
          plaintext.data(), &pLen,
          nullptr,
          cipherBytes.data(), (unsigned long long)cipherBytes.size(),
          nullptr, 0,
          tempNonce, // Temporary fix; see note below
          this->sharedKey
      );

      // Benchmarking: End timing
      Fw::Time end = this->getTime();
      {
          char debugBuf[128];
          std::snprintf(debugBuf, sizeof(debugBuf),
              "Decrypt end: %u sec, %u usec", end.getSeconds(), end.getUSeconds());
          Fw::LogStringArg dbg(debugBuf);
          this->log_ACTIVITY_LO_DebugLog(dbg);
      }

      if (ret != 0) {
          char dbgBuf[100];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "Ascon decryption failed (ret=%d). Possibly incomplete or tampered ciphertext.",
              ret);
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
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
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
      }

      plaintext.resize(pLen);

      // 7) Log the final plaintext length
      {
          char dbgBuf[128];
          std::snprintf(dbgBuf, sizeof(dbgBuf),
              "Decryption success. Plaintext length: %llu", pLen);
          Fw::LogStringArg dbgArg(dbgBuf);
          this->log_ACTIVITY_LO_DebugLog(dbgArg);
      }

      // 8) Convert plaintext to ASCII for logging
      std::string plainAscii(
          reinterpret_cast<const char*>(plaintext.data()),
          plaintext.size()
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

  // ----------------------------------------------------------------------
  // Benchmark
  // ----------------------------------------------------------------------
  void AsconEncryptor::Benchmark_cmdHandler(
    FwOpcodeType opCode,
    U32 cmdSeq,
    U32 length,
    U32 runs
  ) {
    FILE* logFile = fopen("benchmark.csv", "a");
    if (!logFile) {
        this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Failed to open benchmark.csv"));
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
        // Generate a random nonce for each iteration
        U8 nonce[CRYPTO_NPUBBYTES];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t j = 0; j < CRYPTO_NPUBBYTES; ++j) {
            nonce[j] = static_cast<U8>(dis(gen));
        }

        Fw::Time encStart = this->getTime();
        unsigned long long cLen = 0;
        int encRet = crypto_aead_encrypt(
            ciphertext.data(), &cLen,
            plaintext.data(), length,
            nullptr, 0,
            nullptr,
            nonce,
            this->sharedKey
        );
        Fw::Time encEnd = this->getTime();

        if (encRet != 0) {
            this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Benchmark: Encrypt failed"));
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
            nonce,
            this->sharedKey
        );
        Fw::Time decEnd = this->getTime();

        if (decRet != 0) {
            this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Benchmark: Decrypt failed"));
            fclose(logFile);
            this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::EXECUTION_ERROR);
            return;
        }

        U32 decTimeUs = (decEnd.getSeconds() * 1000000 + decEnd.getUSeconds()) -
                       (decStart.getSeconds() * 1000000 + decStart.getUSeconds());

        fprintf(logFile, "%u,%u,%u\n", length, encTimeUs, decTimeUs);
    }

    fclose(logFile);
    this->log_ACTIVITY_LO_DebugLog(Fw::LogStringArg("Benchmark completed"));
    this->cmdResponse_out(opCode, cmdSeq, Fw::CmdResponse::OK);
  }

  // ----------------------------------------------------------------------
  // New port handler implementations
  // ----------------------------------------------------------------------
  void AsconEncryptor::nonceOut_out(NATIVE_INT_TYPE portNum, Fw::Buffer& nonce) {
      this->nonceOut_out(portNum, nonce); // Forward to autogenerated port call
  }

  void AsconEncryptor::cipherOut_out(NATIVE_INT_TYPE portNum, Fw::Buffer& cipher) {
      this->cipherOut_out(portNum, cipher); // Forward to autogenerated port call
  }

} // namespace Components