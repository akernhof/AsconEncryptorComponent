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

def uav_exch():
    HOST = '10.69.0.241'
    PORT = 7700


    #print("[INFO] Setting up UDP socket...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (HOST, PORT)
    # === Generate RSA + EC Key Pairs ===
    generate_and_save_ec_keys()
    generate_and_save_rsa_keys()

    # === Load UAV's EC private key ===
    ec_priv = load_ec_key('private')
    ec_pub = ec_priv.public_key()

    # === Send RSA public key to UGV ===
    rsa_pub_bytes = load_rsa_key('public').export_key()
    send_message(sock, addr, rsa_pub_bytes)

    # === Receive UGV's RSA public key ===
    received_data, sender_addr = receive_message(sock)
    UGV_rsa_pub = RSA.import_key(received_data)
    #print(f"[RECEIVED] RSA Public Key From {sender_addr}:\n{received_data.decode()}")

    # === Send Encrypted EC Public Key to UGV ===
    ec_pub_bytes = ec_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    cipher_rsa_out = PKCS1_OAEP.new(UGV_rsa_pub)
    enc_ec_pub = cipher_rsa_out.encrypt(ec_pub_bytes)
    send_message(sock, addr, enc_ec_pub)

    # === Receive encrypted EC public key from UGV ===
    enc_ugv_ec_pub_bytes, _ = receive_message(sock)
    #print("[UAV] Received encrypted EC public key from UGV")

    # === Decrypt using UAV's private RSA key ===
    cipher_rsa_in = PKCS1_OAEP.new(load_rsa_key('private'))
    ugv_ec_pub_bytes = cipher_rsa_in.decrypt(enc_ugv_ec_pub_bytes)

    # === Deserialize EC public key ===
    ugv_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ugv_ec_pub_bytes)

    # === Derive shared key ===
    shared_secret = ec_priv.exchange(ECDH(), ugv_ec_pub)
    shared_key = sha256(shared_secret).digest()[:16]

    # === Print shared key ===
    #print(f"[UAV] Shared Key: {shared_key.hex()}")
    sock.close()
    return shared_key

#uav_exch()
