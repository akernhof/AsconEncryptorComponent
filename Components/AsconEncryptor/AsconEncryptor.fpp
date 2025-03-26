module Components {

  @ ASCON encryption component for F´
  active component AsconEncryptor {

    @ Encrypts a plaintext string
    async command Encrypt(
        data: string size 1024 @< plaintext as a normal ASCII string to encrypt
        person: U8 @< 1 for UGV, 2 for UAV
        portnumber: U16 @< UDP port to send encrypted data to    
    ) opcode 0x100

    @ Decrypts a ciphertext string
    async command Decrypt(
        data: string size 1024 @< Ciphertext to decrypt 
    ) opcode 0x101

    @ Benchmark encryption/decryption for a given length and number of runs
    async command Benchmark(
        length: U32 @< Message length in bytes
        runs: U32 @< Number of benchmark runs
    ) opcode 0x102

    @ Tracks how many times we've encrypted
    telemetry EncryptionCount: U32

    @ Tracks how many times we've decrypted
    telemetry DecryptionCount: U32

    telemetry EncryptTimeUs: U32  @< Time to encrypt in microseconds
    
    telemetry DecryptTimeUs: U32  @< Time to decrypt in microseconds

    @ Event logged upon successful encryption
    event EncryptionSuccess(
    result: string size 1024 @< Encrypted text or success info
    ) severity activity high format "Encryption success: {}"

    @ Event logged upon successful decryption
    event DecryptionSuccess(
    result: string size 1024 @< Decrypted text or success info
    ) severity activity high format "Decryption success: {}"

    @ A debug event for developer messages
    event DebugLog(
    msg: string size 128 @< Debug message
    ) severity activity low format "DEBUG: {}"

    @ Output port for encrypted data
    output port EncryptedDataOut: Fw.BufferSend

    @ New output ports from the patch
    output port nonceOut: Fw.BufferSend
    output port cipherOut: Fw.BufferSend

    ###############################################################################
    # Standard AC Ports: Required for Channels, Events, Commands, and Parameters  #
    ###############################################################################
    @ Port for requesting the current time
    time get port timeCaller

    @ Port for sending command registrations
    command reg port cmdRegOut

    @ Port for receiving commands
    command recv port cmdIn

    @ Port for sending command responses
    command resp port cmdResponseOut

    @ Port for sending textual representation of events
    text event port logTextOut

    @ Port for sending events to downlink
    event port logOut

    @ Port for sending telemetry channels to downlink
    telemetry port tlmOut

    @ Port to return the value of a parameter
    param get port prmGetOut

    @Port to set the value of a parameter
    param set port prmSetOut
  }
}