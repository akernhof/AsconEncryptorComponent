#UGV Side SENDS CHIRPS (SHOULD BE TRANSMITTING)
import socket
import sys
import random
import os
import struct
import time

#from Key_Exch_UAV import uav_exch
from Key_Exch_UGV import ugv_exch
from socket_comms import send_message
from socket_comms import receive_message
from ascon import ascon_encrypt

def load_shared_key(path="/tmp/shared_key.bin"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Shared key file not found at {path}")
    with open(path, "rb") as f:
        return f.read()


def start_chirper_failsafe():
    shared_key = load_shared_key()
    HOST = '10.69.0.222'
    PORT = 9090

    #shared_key = uav_exch()
    #shared_key = load_shared_key()
    sock_c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr_c = (HOST, PORT) 
    print("starting chirps")

    while True:
        ran_chirp = random.randint(1, 1708)
        ran_chirp_byte = ran_chirp.to_bytes(2, 'big')
        nonce = os.urandom(16)
        cipher = ascon_encrypt(shared_key, nonce, b"", ran_chirp_byte)
        send_message(sock_c, addr_c, nonce)
        send_message(sock_c, addr_c, cipher)
        time.sleep(1)

start_chirper_failsafe()
