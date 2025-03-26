import struct
def send_message(sock, addr, message_bytes):
    """
    Send a message over UDP with a length header (4 bytes).
    """
    msg_len = len(message_bytes)
    sock.sendto(struct.pack("!I", msg_len), addr)  # Send message length first
    sock.sendto(message_bytes, addr)               # Then send actual message

def receive_message(sock):
    """
    Receive a length-prefixed UDP message.
    :return: (message_bytes, sender_address)
    """
    length_data, addr = sock.recvfrom(4)  # Receive length prefix
    msg_len = struct.unpack("!I", length_data)[0]

    message_data, _ = sock.recvfrom(msg_len)  # Receive message
    return message_data, addr
    
def receive_message_from_fprime(sock, buffer_size=1024):
    """
    Receives a single UDP message from the F' component that includes both
    the nonce and the cipher in one buffer. Assumes the first 16 bytes are the nonce.
    
    :return: (nonce_bytes, cipher_bytes, sender_address)
    """
    message_data, addr = sock.recvfrom(buffer_size)

    if len(message_data) < 16:
        raise ValueError(f"Message too short to contain a nonce: {len(message_data)} bytes")

    nonce = message_data[:16]
    cipher = message_data[16:]
    return nonce, cipher, addr

