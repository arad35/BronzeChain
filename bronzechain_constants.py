"""module to save BronzeChain application constants"""
# addresses of all peers in network
# when connection server will be added, hardcoded addresses will be replaced
PEERS = []
CONNECT_PORT = None
TIMEOUT = 60
HOP_COUNT = 3


def set_constants(peers, connect_port, timeout, hop_count):
    global PEERS, CONNECT_PORT, TIMEOUT, HOP_COUNT
    PEERS = peers
    CONNECT_PORT = connect_port
    TIMEOUT = timeout
    HOP_COUNT = hop_count
