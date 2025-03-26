import socket
import struct
from Key_Gen import generate_and_save_rsa_keys
from Key_Gen import generate_and_save_ec_keys
from key_load import load_rsa_key
from key_load import load_ec_key
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from hashlib import sha256


from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


#print(f"[INFO] Listening on UDP {HOST}:{PORT}...")

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

def ugv_exch():
    HOST = '0.0.0.0'
    PORT = 7700

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))
    # === Generate RSA + EC Key Pairs ===
    generate_and_save_ec_keys()
    generate_and_save_rsa_keys()

    # === Load UGV's EC private key ===
    ec_priv = load_ec_key('private')

    # === Receive RSA public key from UAV ===
    received_data, sender_addr = receive_message(server)
    UAV_rsa_pub = RSA.import_key(received_data)    

    # === Send UGV's RSA public key ===
    UGV_rsa_pub_bytes = load_rsa_key('public').export_key()
    send_message(server, sender_addr, UGV_rsa_pub_bytes)

    # === Receive Encrypted EC Key from UAV ===
    enc_uav_ec_pub_bytes, _ = receive_message(server)

    # === Decrypt UAV's EC public key ===
    cipher_rsa_in = PKCS1_OAEP.new(load_rsa_key('private'))
    uav_ec_pub_bytes = cipher_rsa_in.decrypt(enc_uav_ec_pub_bytes)

    uav_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uav_ec_pub_bytes)

    # === Derive Shared Key ===
    shared_secret = ec_priv.exchange(ECDH(), uav_ec_pub)
    shared_key = sha256(shared_secret).digest()[:16]

    print(f"[UGV] Shared Key: {shared_key.hex()}")

    # === Load UGV's EC public key ===
    ec_pub = ec_priv.public_key()

    # === Serialize UGV EC public key ===
    ec_pub_bytes = ec_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # === Encrypt UGV EC pubkey with UAV RSA pubkey ===
    cipher_rsa_out = PKCS1_OAEP.new(UAV_rsa_pub)
    enc_ec_pub = cipher_rsa_out.encrypt(ec_pub_bytes)

    # === Send Encrypted EC Public Key to UAV ===
    send_message(server, sender_addr, enc_ec_pub)
    
    # After shared_key is derived
    with open("/tmp/shared_key.bin", "wb") as f:
        f.write(shared_key)

    # === Verify the written key ===
    with open("/tmp/shared_key.bin", "rb") as f:
        read_key = f.read()
    
    # Compare the original shared_key with the one read from file
    if read_key == shared_key:
        print("[VERIFICATION] Shared key matches the stored key in /tmp/shared_key.bin")
    else:
        print("[VERIFICATION ERROR] Shared key does NOT match the stored key!")
        print(f"Original: {shared_key.hex()}")
        print(f"Read:     {read_key.hex()}")

    server.close()
    return shared_key

ugv_exch()