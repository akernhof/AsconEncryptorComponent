import socket
import os
import traceback
from ascon import ascon_decrypt

# Configuration
IP = "0.0.0.0"
PORT = 12345
KEY_FILE = "/tmp/shared_key.bin"
KEY_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16

def load_shared_key(filepath):
    if not os.path.exists(filepath):
        print(f"Error: Key file {filepath} not found.")
        return None
    with open(filepath, "rb") as f:
        key = f.read(KEY_SIZE)
        if len(key) != KEY_SIZE:
            print(f"Error: Key file must contain exactly {KEY_SIZE} bytes, got {len(key)}.")
            return None
        return key

def setup_udp_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"Listening on {ip}:{port}...")
    return sock

def decrypt_data(key, nonce, ciphertext):
    try:
        print(f"Decrypting with:")
        print(f"  Key: {key.hex().upper()}")
        print(f"  Nonce: {nonce.hex().upper()}")
        print(f"  Ciphertext: {ciphertext.hex().upper()}")
        plaintext = ascon_decrypt(
            key=key,
            nonce=nonce,
            ciphertext=ciphertext,
            associateddata=b"",
            variant="Ascon-128a"
        )
        return plaintext
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None

def main():
    key = load_shared_key(KEY_FILE)
    if key is None:
        return
    print(f"Loaded shared key: {key.hex().upper()}")

    sock = setup_udp_socket(IP, PORT)

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"Received {len(data)} bytes from {addr}")

            if len(data) < NONCE_SIZE + TAG_SIZE + 1:
                print("Error: Packet too small.")
                continue

            nonce = data[:NONCE_SIZE]
            ciphertext = data[NONCE_SIZE:]

            nonce_hex = nonce.hex().upper()
            ciphertext_hex = ciphertext.hex().upper()
            print(f"Nonce: {nonce_hex}")
            print(f"Ciphertext (with tag): {ciphertext_hex}")

            plaintext = decrypt_data(key, nonce, ciphertext)
            if plaintext is None:
                print("Decryption returned None (likely tag verification failed)")
            elif plaintext:
                try:
                    plaintext_str = plaintext.decode("ascii")
                    print(f"Decrypted plaintext: '{plaintext_str}'")
                except UnicodeDecodeError:
                    plaintext_hex = plaintext.hex().upper()
                    print(f"Decrypted plaintext (raw bytes): {plaintext_hex}")
            else:
                print("Decrypted plaintext is empty")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()