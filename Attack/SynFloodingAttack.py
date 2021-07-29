import string
from scapy.all import *
from threading import Thread
from random import *

def randNum():
    return randint(1000, 9000)

PORT = 22
SRC = "127.0.0.1"
DST = RandIP()
TEXT = (string.ascii_letters+string.digits)*10

Attack_Index = 0

IP_PACKET = IP()
IP_PACKET.src = SRC
IP_PACKET.dst = DST
IP_PACKET.len = 65535

TCP_PACKET = TCP()
TCP_PACKET.sport = randNum()
TCP_PACKET.dport = 4321
TCP_PACKET.flags = "S"
TCP_PACKET.seq = randNum()
TCP_PACKET.window = randNum()

RAW_PACKET = Raw()
RAW_PACKET.load = TEXT

str = f"""
===============================================
IP Packet : {IP_PACKET}
TCP Packet : {TCP_PACKET}
RAW Packet : {RAW_PACKET}
===============================================
"""

print(str)
send(IP_PACKET/TCP_PACKET/RAW_PACKET)
