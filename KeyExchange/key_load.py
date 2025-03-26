from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import os


def load_rsa_key(key_type, key_dir='keys'):
    """
    Load RSA private or public key from PEM file.

    :param key_type: 'private' or 'public'
    :param key_dir: Directory where the keys are stored
    :return: RSA key object
    """
    filename = f"rsa_{key_type}.pem"
    key_path = os.path.join(key_dir, filename)

    with open(key_path, 'rb') as f:
        key_data = f.read()

    return RSA.import_key(key_data)

def load_ec_key(key_type, key_dir='keys'):
    """
    Load EC private or public key from PEM file.

    :param key_type: 'private' or 'public'
    :param key_dir: Directory where the keys are stored
    :return: EC key object
    """
    filename = f"ec_{key_type}.pem"
    key_path = os.path.join(key_dir, filename)

    with open(key_path, 'rb') as f:
        key_data = f.read()

    if key_type == 'private':
        return serialization.load_pem_private_key(key_data, password=None)
    elif key_type == 'public':
        return serialization.load_pem_public_key(key_data)
    else:
        raise ValueError("key_type must be 'private' or 'public'")