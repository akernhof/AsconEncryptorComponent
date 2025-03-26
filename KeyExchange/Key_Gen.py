from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

def generate_and_save_rsa_keys(output_dir='keys', key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'rsa_private.pem'), 'wb') as f:
        f.write(private_key)

    with open(os.path.join(output_dir, 'rsa_public.pem'), 'wb') as f:
        f.write(public_key)

    print("[+] RSA key pair saved to", output_dir)


def generate_and_save_ec_keys(output_dir='keys'):
    ec_private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize private key
    ec_private_bytes = ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    ec_public_key = ec_private_key.public_key()
    ec_public_bytes = ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'ec_private.pem'), 'wb') as f:
        f.write(ec_private_bytes)

    with open(os.path.join(output_dir, 'ec_public.pem'), 'wb') as f:
        f.write(ec_public_bytes)

    print("[+] EC key pair saved to", output_dir)


if __name__ == '__main__':
    generate_and_save_rsa_keys()
    generate_and_save_ec_keys()
