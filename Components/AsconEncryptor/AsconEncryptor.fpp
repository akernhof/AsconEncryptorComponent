module Components {

  @ ASCON encryption component for F´
  active component AsconEncryptor {

    # One async command/port is required for active components
    # This should be overridden by the developers with a useful command/port

    @ Encrypts a plaintext string
    async command Encrypt(
        data: string size 1024 @< plaintext as a normal ASCII string to encrypt
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
    ) severity activity high format "DEBUG: {}"


    @ (Optional) If you need to pass data in/out as raw bytes
    # async input port Encrypt_Input: Fw.Buffer
    # output port Encrypt_Output: Fw.Buffer
    # async input port Decrypt_Input: Fw.Buffer
    # output port Decrypt_Output: Fw.Buffer

    #####################
    # Example placeholders
    #####################

    # @ Example async command
    # async command COMMAND_NAME(param_name: U32)

    # @ Example telemetry counter
    # telemetry ExampleCounter: U64

    # @ Example event
    # event ExampleStateEvent(example_state: Fw.On) severity activity high id 0 format "State set to {}"

    # @ Example port: receiving calls from the rate group
    # sync input port run: Svc.Sched

    # @ Example parameter
    # param PARAMETER_NAME: U32

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
