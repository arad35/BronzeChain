"""blockchain.py
Classes for managing a blockchain peer"""

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import threading
from socket import *
import copy
import binascii
from datetime import datetime
import hashlib
import json
from typing import List
import traceback
import time
# from json_print import pretty_print_json


def sha256(message):
    """hashes a message
    returns hash as a string"""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()


def print_long_string(s, max_length=100):
    """Split a long string into lines no longer than max_length."""
    lines = []
    while len(s) > max_length:
        # Find the last space within the max_length
        split_index = s.rfind(' ', 0, max_length)
        if split_index == -1:
            # If there's no space within the max_length, split at max_length
            split_index = max_length
        # Append the line to the list
        lines.append(s[:split_index])
        # Update the string to exclude the processed part
        s = s[split_index:].lstrip()
    # Append the last part of the string (or the whole string if short enough)
    if s:
        lines.append(s)

    for line in lines:
        print(line)


class PacketHandlingError(Exception):
    pass


class Transaction:
    """A class for representing a transaction"""

    def __init__(self, sender: RSA.RsaKey, receiver: RSA.RsaKey, value: float,
                 timestamp: datetime, tx_hash: str, signature: str):
        """transaction initialization by directly assigning properties"""
        # sender and receiver public keys
        self.sender = sender
        self.receiver = receiver

        self.value = value
        self.timestamp = timestamp
        self.tx_hash = tx_hash
        self.signature = signature

    def to_json(self):
        """return json representation of the transaction"""
        return json.dumps({
            "sender": binascii.hexlify(self.sender.export_key()).decode(),
            "receiver": binascii.hexlify(self.receiver.export_key()).decode(),
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "tx_hash": self.tx_hash,
            "signature": self.signature
        })

    @classmethod
    def from_json(cls, json_data):
        """creates and returns a transaction object from json data"""
        try:
            # load data
            data = json.loads(json_data)
            sender = RSA.import_key(binascii.unhexlify(data["sender"]))
            receiver = RSA.import_key(binascii.unhexlify(data["receiver"]))
            value = data["value"]
            timestamp = datetime.fromisoformat(data["timestamp"])
            tx_hash, signature = data["tx_hash"], data["signature"]

        except Exception as e:
            # possible errors: data doesn't fit transaction format / missing properties
            # / data doesn't fit type (e.g. RSAkey)
            print(f"\ndata was not a valid transaction\n{e}", json_data)
            return f"data was not a valid transaction\n{e}"

        else:
            return cls(sender, receiver, value, timestamp, tx_hash, signature)

    @classmethod
    def create_transaction(cls, sender, receiver, value, signer):
        """creates a new transaction
        sender: sender's private key
        receiver: receiver's private key
        value: amount to be transferred
        signer: peer's signer object
        returns: new transaction"""
        timestamp = datetime.now()
        data = f"{binascii.hexlify(sender.export_key()).decode()}{binascii.hexlify(receiver.export_key()).decode()}{value}{timestamp.isoformat()}"
        print(f"og data:\n{data}")
        tx_hash = sha256(data)
        signature = cls.sign(data, signer)
        return cls(sender, receiver, value, timestamp, tx_hash, signature)

    @staticmethod
    def sign(data, signer):
        """sign the transaction using the user's private key
        data: transaction data
        signer: peer's signer object
        return: signature in string format"""
        h = SHA256.new(data.encode('utf-8'))
        return binascii.hexlify(signer.sign(h)).decode('ASCII')


class Block:
    """A class for representing a single block"""

    def __init__(self, transactions: List[Transaction], transactions_hash: str,
                 difficulty: int, reward: float, previous_hash: str,
                 nonce: int = None, miner: RSA.RsaKey = None, timestamp: datetime = None):
        """block initialization by directly assigning properties
        nonce, miner and timestamp are None in case block was not yet mined"""

        self.transactions = copy.copy(transactions)
        self.transaction_hash = transactions_hash
        self.difficulty = difficulty
        self.reward = reward
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.miner = miner
        self.timestamp = timestamp

    def to_json(self):
        """return json representation of the block"""
        return json.dumps({
            "transactions": [tx.to_json() for tx in self.transactions],
            "transaction_hash": self.transaction_hash,
            "difficulty": self.difficulty,
            "reward": self.reward,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "miner": binascii.hexlify(self.miner.export_key()).decode(),
            "timestamp": self.timestamp.isoformat()
        })

    @classmethod
    def from_json(cls, json_data):
        """create and return Block object from json data"""
        data = json.loads(json_data)
        transactions = [Transaction.from_json(tx) for tx in data["transactions"]]
        transaction_hash = data["transaction_hash"]
        difficulty = data["difficulty"]
        reward = data["reward"]
        previous_hash = data["previous_hash"]
        nonce = data["nonce"]
        miner = RSA.import_key(binascii.unhexlify(data["miner"]))
        timestamp = datetime.fromisoformat(data["timestamp"])
        return cls(transactions, transaction_hash, difficulty, reward, previous_hash, nonce, miner, timestamp)

    @classmethod
    def create_block(cls, transactions, difficulty, reward, previous_hash):
        """creates and returns a new block"""
        transaction_hash = cls.compute_transaction_hash(transactions)
        return cls(transactions, transaction_hash, difficulty, reward, previous_hash)

    @classmethod
    def create_genesis_block(cls):
        """Create and returns genesis block of the blockchain"""
        transactions = []
        transactions_hash = "0"
        difficulty = 1
        reward = 0
        previous_hash = "0"
        timestamp = datetime.now()
        return cls(transactions, transactions_hash, difficulty, reward, previous_hash, timestamp=timestamp)

    @staticmethod
    def compute_transaction_hash(transactions):
        """computes and returns hash of all transactions"""
        concatenated_hash = ''.join([tx.tx_hash for tx in transactions])
        return sha256(concatenated_hash)

    def compute_hash(self):
        """computes and returns the hash of the block"""
        block_data = f"{self.transaction_hash}{self.difficulty}{self.reward}{self.previous_hash}{self.nonce}{self.timestamp}"
        return sha256(block_data)

    def validate_difficulty(self):
        """checks if hash of block suits difficulty
        returns: a boolean indicating whether hash suits difficulty"""
        block_hash = self.compute_hash()
        if block_hash.endswith("0" * self.difficulty):
            return True
        else:
            return False

    def mine_block(self, miner):
        """Implements proof of work: finds a suitable nonce that satisfies difficulty
        miner: public key of miner
        updates: nonce, miner and timestamp properties"""
        self.nonce = 0
        self.timestamp = datetime.now()
        success = self.validate_difficulty()

        while not success:
            self.nonce += 1
            success = self.validate_difficulty()

        self.miner = miner
        self.timestamp = datetime.now()


class Blockchain:
    """Represents the entire blockchain"""

    def __init__(self):
        """Initialize blockchain with the genesis block"""
        self.chain = [Block.create_genesis_block()]

    def add_block_to_chain(self, block):
        """Add a block to the blockchain if valid"""
        self.chain.append(block)

    def get_last_block(self):
        """Get the last block in the blockchain"""
        return self.chain[-1]

    def is_chain_valid(self):
        """Check the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.previous_hash != previous_block.compute_hash():
                return False

            if not current_block.validate_difficulty():
                return False

        return True

    def verify_block(self, block):
        """Comprehensive validation of a block before adding to the chain"""
        last_block = self.get_last_block()

        if block.previous_hash != last_block.compute_hash():
            return False

        if not block.validate_difficulty():
            return False

        return True


class Peer:
    """Represents a peer in the blockchain network"""

    def __init__(self, name, peers, connect_port, balance=50, miner=False, hop_max=3, refresh_time=120):
        # initialize networking properties
        self.ip = gethostbyname(gethostname())
        self.packet_cache = set() # stores hashes of last packets

        # properties for sending
        self.send_sock = socket(AF_INET, SOCK_STREAM)
        self.peers = peers

        # properties for receiving
        self.connect_port = connect_port
        self.connect_sock = socket(AF_INET, SOCK_STREAM)

        # net constants
        self.hop_max = hop_max
        self.refresh_time = refresh_time

        # identifying properties
        self.name = name
        self.balance = balance
        self._private_key = RSA.generate(1024)
        self.public_key = self._private_key.public_key()

        # blockchain properties
        self.verified_transactions = []
        self.blockchain = Blockchain()
        self.miner = miner  # flag indicating whether peer is a miner
        self.peer_database = dict()  # address, name, public key, miner status

    @property
    def identity(self):
        """hexadecimal representation of public key"""
        return binascii.hexlify(self.public_key.export_key()).decode("utf-8")

    @property
    def signer(self):
        """returns signer object of the peer"""
        return PKCS1_v1_5.new(self._private_key)

    def update_peer(self, address, name, public_key):
        """update peer info in database"""
        self.peer_database[address] = [name, public_key]
        print(f"\nupdated peer {address} in database", self.peer_database[address])

    def fetch_public_key(self, peer_name):
        """fetch public key of peer by name
        returns public key if found, false if not found"""
        for name, public_key in self.peer_database.values():
            if peer_name == name:
                return public_key

        # name not found in database
        return False

    def compute_packet_hash(self, data):
        """compute hash of a packet accordingly to its type
        data: packet in json format"""
        dict_data = json.loads(data)

        if dict_data["type"] == "Message":
            # return hash of the error message contents + timestamp
            message = dict_data["message"]
            # replace original packet data in its hash
            data_hash = self.compute_packet_hash(dict_data["data"])
            timestamp = dict_data["timestamp"]

            data = f"{message}{data_hash}{timestamp}"
            return sha256(data)

        elif dict_data["type"] == "Hello":
            # return hash of the Hello message contents + timestamp
            address = dict_data["address"]
            name = dict_data["name"]
            public_key = dict_data["public_key"]
            timestamp = dict_data["timestamp"]

            data = f"{address}{name}{public_key}{timestamp}"
            return sha256(data)

        elif dict_data["type"] == "Transaction":
            # return transaction hash
            return Transaction.from_json(data).tx_hash

        elif dict_data["type"] == "Block":
            # return block hash
            return Block.from_json(data).compute_hash()

    def add_packet_to_cache(self, data):
        """add a packet to cache
        data: packet in json format"""
        packet_hash = self.compute_packet_hash(data)
        self.packet_cache.add(packet_hash)
        print(f"\nadded packet to cache. data:\n{data}\nhash:{packet_hash}")

    def is_packet_in_cache(self, data):
        """check if a packet is already in cache
        data: packet in json format
        return: boolean indicating whether packet is already in cache"""
        packet_hash = self.compute_packet_hash(data)
        if packet_hash in self.packet_cache:
            return True

        return False

    def create_transaction(self, receiver, value):
        """creates a new transaction and adds it to verified_transactions list
        receiver: public key of receiver
        value: amount to be sent
        returns new transaction"""
        new_transaction = Transaction.create_transaction(self.public_key, receiver, value, self.signer)
        print("\nnew transaction created:\n", new_transaction.to_json())
        return new_transaction

    @staticmethod
    def verify_transaction(transaction: Transaction):
        """verifies validity of transaction
        checks hash and signature
        returns true if transaction is valid and suitable error message otherwise"""
        json_data = transaction.to_json()
        data = json.loads(json_data)

        # verify hash
        string_data = f"{data['sender']}{data['receiver']}{data['value']}{data['timestamp']}"
        if data["tx_hash"] != sha256(string_data):

            return "transaction hash is invalid"

        # verify signature
        verifier = PKCS1_v1_5.new(transaction.sender)
        h = SHA256.new(string_data.encode())
        if not verifier.verify(h, binascii.unhexlify(data["signature"])):
            return "transaction signature is invalid"

        return True

    def add_transaction(self, transaction):
        """adds transaction to verified transactions"""
        self.verified_transactions.append(transaction)
        print("\nnew transaction added:\n", transaction.to_json())

    def send_data(self, json_data, new_data=False, data_type=None):
        """sends data to all peers in network
        adds type and hop count properties to packet
        json_data: json data
        new_data: true if data is sent in the first time, false if is received and propagated
        data_type: type of data- Transaction, Block, Hello or Message"""
        dict_data = json.loads(json_data)

        # suit a new packet to the BronzeChain protocol
        if new_data:
            dict_data["type"] = data_type
            dict_data["hop_count"] = self.hop_max

            if "timestamp" not in dict_data:
                dict_data["timestamp"] = datetime.now().isoformat()

            # if packet is new add it to cache
            self.add_packet_to_cache(json.dumps(dict_data))

        else:
            if dict_data["hop_count"] == 0:
                print(f'\nmax hop count reached for {data_type}:\n', json.dumps(dict_data))

            data_type = dict_data["type"]
            # decrease hop count
            dict_data["hop_count"] = dict_data["hop_count"] - 1

        data = json.dumps(dict_data)
        # send transaction to all peers
        for addr in self.peers:
            try:
                print(addr)
                time.sleep(2)
                self.send_sock.connect(addr)
                self.send_sock.sendall(data.encode())
                if new_data: print("\ncreated new packet")
                else: print("\npasses a packet")
                print(f'\nsent {data_type} to {addr}:\n', data)

            # socket error
            except OSError as e:
                if e.winerror in {10022, 10038}:
                    print(f"\nSpecific WinError occurred while sending {data_type} to {addr}: {e.winerror}\n{e}")
                    traceback.print_exc()
                if e.winerror == 10061:
                    print(f"\n{addr} is unavailable")

            finally:
                self.send_sock.close()
                # Reinitialize the socket for the next connection attempt
                self.send_sock = socket(AF_INET, SOCK_STREAM)

    def send_transaction(self, transaction):
        """sends a new transaction to all peers in network
        transaction: transaction to be sent
        hop_count: hop count of transaction packet
        -999 placeholder value"""

        data = transaction.to_json()
        self.send_data(data, new_data=True, data_type="Transaction")

    def send_block(self, block):
        """Send a newly mined block to all peers"""
        data = block.to_json()
        self.send_data(data, new_data=True, data_type="Block")

    def send_hello(self, send_me_hello=False):
        """sends a new hello packet to all peers in network
        send_me_hello: whether peers should send back hello (peer discovery)"""

        # crafting hello packet
        data = json.dumps({'address': (self.ip, self.connect_port),
                           "name": self.name,
                           "public_key": self.identity,
                           "send_me_hello": send_me_hello})

        self.send_data(data, new_data=True, data_type="Hello")

    def notify_error(self, sock, message, data):
        """print and sends a new error message
        message: error message
        data: string data received from peer"""
        print(f"\nerror from {sock.getpeername()}:\n{message}\n{data}")

        data_with_message = json.dumps({"message": message, "data": data})
        self.send_data(data_with_message, new_data=True, data_type="Message")

    def receive_data(self):
        """thread for connecting and receiving data from other peers"""
        sock = self.connect_sock
        sock.bind((self.ip, self.connect_port))
        sock.listen(5)

        while True:
            receive_sock, _ = sock.accept()

            peer_thread = threading.Thread(target= self.receive_from_peer, args=(receive_sock,))
            peer_thread.daemon = True
            peer_thread.start()

    def recv_all(self, sock):
        """receive all the data from a socket
        returns a string containing all data"""
        data = b""
        while True:
            chunk = sock.recv(1024)

            if not chunk:
                # finished scanning data
                break

            data += chunk

        return data

    def receive_from_peer(self, sock: SocketType):
        """thread for receiving data from another peer"""

        try:
            # receive data
            try:
                json_data = self.recv_all(sock).decode()
            # socket error (imported socket as *)
            except error or OSError as e:
                print(f"\nsocket error while receiving data from {sock.getpeername()}\n{e}")
                raise PacketHandlingError

            # load data
            try:
                data = json.loads(json_data)

            except Exception as e:
                self.notify_error(sock, f"data wasn't a valid json\n{e}", json_data)
                raise PacketHandlingError

            # check if packet is already in cache
            if self.is_packet_in_cache(json_data):
                print("packet is already in cache\n", json_data)
                raise PacketHandlingError

            # check hop count
            if data["hop_count"] < 0:
                self.notify_error(sock, "hop count exceeded", json_data)
                raise PacketHandlingError

            try:
                # process message
                # return without propagating packet if processing was unsuccessful
                if data["type"] == "Transaction":
                    # process transaction
                    # success value - processing completed successfully
                    success = self.handle_transaction(sock, json_data)
                    if not success: raise PacketHandlingError

                elif data["type"] == "Block":
                    # process block
                    # success value - processing completed successfully
                    success = self.handle_block(sock, json_data)
                    if not success: raise PacketHandlingError

                elif data["type"] == "Hello":
                    # process hello message
                    # success value - processing completed successfully
                    success = self.handle_hello(sock, json_data)
                    if not success: raise PacketHandlingError

                elif data["type"] == "Message":
                    # print error message
                    self.print_message(sock, json_data)

                else:
                    self.notify_error(sock, "json data of unfamiliar type", json_data)
                    raise PacketHandlingError

            except KeyError as e:
                self.notify_error(sock, f"data was not a valid BronzeChain message\n{e}", data)
                raise PacketHandlingError

        except PacketHandlingError:
            # unsuccessful processing
            pass

        else:
            self.add_packet_to_cache(json_data)
            # after data processing successfully, propagate data in network
            self.send_data(json_data)

        finally:
            sock.close()

    def handle_transaction(self, sock, transaction_json):
        """handles a received transaction
        sock: socket for interaction with sender
        transaction_json: json data with the transaction
        returns: True if transaction processed successfully, False otherwise"""
        transaction = Transaction.from_json(transaction_json)

        # error in parsing json
        if isinstance(transaction, str):
            error_message = transaction
            self.notify_error(sock, error_message, transaction_json)
            return False

        # invalid transaction (wrong hash or signature)
        verification = self.verify_transaction(transaction)
        if isinstance(verification, str):
            error_message = verification
            self.notify_error(sock, error_message, transaction_json)
            return False

        # valid transaction,send and add to verified transactions
        self.add_transaction(transaction)
        return True

    def handle_block(self, sock, block_json):
        """Handle the receipt of a new block from another peer"""
        block = Block.from_json(block_json)

        if self.blockchain.verify_block(block):
            self.blockchain.add_block_to_chain(block)
            print("Block added to the blockchain")
            return True
        else:
            print("Received block is invalid")
            return False

    def handle_hello(self, sock, hello_packet):
        """handles an hello packet
        sock: socket for interaction with sender
        transaction_json: json data with the transaction"""
        try:
            # load data
            data = json.loads(hello_packet)
            address = tuple(data["address"])
            name = data["name"]
            public_key = RSA.import_key(binascii.unhexlify(data["public_key"]))

        except Exception as e:
            # possible errors: data doesn't fit hello packet format / missing properties
            # / data doesn't fit type (e.g. RSAkey)
            self.notify_error(sock, f"data was not a valid hello packet\n{e}", hello_packet)
            traceback.print_exc()
            return False

        else:
            # update peer database
            print(f"\nreceived hello from {sock.getpeername()}:\n", hello_packet)
            self.update_peer(address, name, public_key)

            # send back hello if requested
            pass
            if data["send_me_hello"]:
                self.send_hello(send_me_hello=False)

            return True

    def print_message(self, sock, json_data):
        """print an error message"""
        try:
            data = json.loads(json_data)
            message = data["message"]
            og_data = data["data"]

        except Exception as e:
            # possible errors: data doesn't fit message packet format / missing properties
            print(f"\nerror from {sock.getpeername()}:data was not a valid error message\n{e}\n{json_data}")

        else:
            # print the received error message
            print(f"\nerror from {sock.getpeername()}:\n{message}\n{og_data}")

    def mine_new_block(self):
        """Create, mine, and send a new block"""
        last_block = self.blockchain.get_last_block()
        previous_hash = last_block.compute_hash()
        difficulty = last_block.difficulty  # change to self difficulty
        reward = 50  # change to self reward

        new_block = Block.create_block(
            self.verified_transactions, difficulty, reward, previous_hash
        )

        new_block.mine_block(self.public_key)

        if self.blockchain.verify_block(new_block):
            self.blockchain.add_block_to_chain(new_block)
            self.verified_transactions = []
            self.send_block(new_block)
        else:
            print("Mined block is invalid. Retrying...")
            # return failure indication

    def miner_thread(self):
        """Constantly check for new transactions and mine new blocks"""
        while self.miner:
            if len(self.verified_transactions) >= 2:
                self.mine_new_block()
            time.sleep(5)

    def cleanup_thread(self):
        """clear packet cache once in refresh time"""

        while True:
            time.sleep(self.refresh_time)
            self.packet_cache.clear()
            print(f"""packet cache cleanup at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}""")

    def start(self):
        """start BronzeChain"""
        self.send_hello(send_me_hello=True)

        receive_thread = threading.Thread(target=self.receive_data)
        receive_thread.start()

        cleanup_thread = threading.Thread(target= self.cleanup_thread)
        cleanup_thread.daemon = True
        cleanup_thread.start()

        if self.miner:
            miner_thread = threading.Thread(target=self.miner_thread)
            miner_thread.start()


# gui
