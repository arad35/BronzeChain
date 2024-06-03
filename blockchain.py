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


def sha256(message):
    """hashes a message
    returns hash as a string"""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()


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
            receiver = RSA.import_key(binascii.unhexlify(data["sender"]))
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
        data = f"{sender.export_key().decode()}{receiver.export_key().decode()}{value}{timestamp.isoformat()}"
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

        return cls(transactions, transactions_hash, difficulty, reward, previous_hash)

    @staticmethod
    def compute_transaction_hash(transactions):
        """computes and returns hash of all transactions"""
        concatenated_hash = ''.join(tx.tx_hash() for tx in transactions)
        return sha256(concatenated_hash)

    def block_data(self):
        """returns a string containing block data"""
        return f"{self.transaction_hash}{self.difficulty}{self.reward}{self.previous_hash}{self.nonce}{self.timestamp}"

    def validate_difficulty(self, data):
        """checks if hash of block suits difficulty
        data: block data
        returns: a tuple that contains:
        1. block hash
        2. a boolean indicating whether hash suits difficulty"""

        block_hash = sha256(data)

        if block_hash.endswith("0" * self.difficulty):
            return block_hash, True
        else:
            return block_hash, False

    def mine_block(self, miner):
        """Implements proof of work: finds a suitable nonce that satisfies difficulty
        sender: public key of sender
        updates: nonce, miner and timestamp properties
        returns: block hash"""

        # checking suitability for nonce 0
        self.nonce = 0
        self.timestamp = datetime.now()
        data = self.block_data()
        block_hash, success = self.validate_difficulty(data)

        # increasing nonce until difficulty criteria is satisfied
        while not success:
            self.nonce += 1
            data = self.block_data()
            block_hash, success = self.validate_difficulty(data)

        # updating miner and timestamp
        self.miner = miner
        self.timestamp = datetime.now()

        return block_hash


class Blockchain():
    pass


class Peer:
    """Represents a peer in the blockchain network"""

    def __init__(self, name, peers, connect_port, balance=50, miner=False, time_out=60, hop_max=3):
        # initialize networking properties
        self.ip = gethostbyname(gethostname())

        # properties for sending
        self.send_sock = socket(AF_INET, SOCK_STREAM)
        self.peers = peers

        # properties for receiving
        self.connect_port = connect_port
        self.connect_sock = socket(AF_INET, SOCK_STREAM)

        # net constants
        self.timeout = time_out
        self.hop_max = hop_max

        # identity properties
        self.name = name
        self.balance = balance
        self._private_key = RSA.generate(1024)
        self.public_key = self._private_key.public_key()

        # blockchain properties
        self.verified_transactions = []
        self.blockchain = Blockchain()
        # flag indicating whether peer is a miner
        self.miner = miner
        # address, name, public key, miner status
        self.peer_database = dict()

    @property
    def identity(self):
        """hexadecimal representation of public key"""
        return binascii.hexlify(self.public_key.export_key()).decode("utf-8")

    @property
    def signer(self):
        """returns signer object of the peer"""
        return PKCS1_v1_5.new(self._private_key)

    def update_peer(self, address, name, public_key, miner):
        """update peer info in database"""
        self.peer_database[address] = [name, public_key, miner]
        print(f"\nupdated peer {address} in database", self.peer_database[address])

    def fetch_public_key(self, peer_name):
        """fetch public key of peer by name
        returns public key if found, false if not found"""
        for name, public_key, _ in self.peer_database.values():
            if peer_name == name:
                return public_key

        # name not found in database
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

        # updating type and hop count properties
        if new_data:
            dict_data["type"] = data_type
            dict_data["hop_count"] = self.hop_max
        else:
            data_type = dict_data["type"]
            dict_data["hop_count"] = dict_data["hop_count"] - 1

        data = json.dumps(dict_data)
        # send transaction to all peers
        for addr in self.peers:
            try:
                print(addr)
                time.sleep(2)
                self.send_sock.connect(addr)
                self.send_sock.sendall(data.encode())
                print(f'\nsent {data_type} to {addr}:\n', data)

            # socket error
            except OSError as e:
                if e.winerror in {10022, 10038}:
                    print(f"\nSpecific WinError occurred while sending {data_type} to {addr}: {e.winerror}\n{e}")
                    traceback.print_exc()
                else:
                    print(f"\nSocket error occurred while sending {data_type} to {addr}\n{e}")
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

    def send_hello(self, send_me_hello=False):
        """sends a new hello packet to all peers in network
        send_me_hello: whether peers should send back hello (peer discovery)
        hop_count: hop count of transaction packet
        -999 placeholder value"""

        # crafting hello packet
        data = json.dumps({'address': (self.ip, self.connect_port),
                           "name": self.name,
                           "public_key": self.identity,
                           "miner": self.miner,
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

    def receive_from_peer(self, sock: SocketType):
        """thread for receiving data from another peer"""

        # close socket if inactive for too long
        try:
            sock.settimeout(self.timeout)

            while True:
                json_data = sock.recv(1024).decode()

                # load data
                try:
                    data = json.loads(json_data)

                except ValueError as e:
                    self.notify_error(sock, f"data wasn't a valid json\n{e}", json_data)
                    continue

                # check hop count status
                if data["hop_count"] < 0:
                    self.notify_error(sock, "hop count exceeded", json_data)
                    continue

                try:
                    # process message
                    if data["type"] == "Transaction":
                        # process transaction
                        # success value - processing completed successfully
                        success = self.handle_transaction(sock, json_data)
                        if not success: continue

                    elif data["type"] == "Block":
                        pass

                    elif data["type"] == "Hello":
                        # process hello message
                        # success value - processing completed successfully
                        success = self.handle_hello(sock, json_data)
                        if not success: continue

                    elif data["type"] == "Message":
                        # print error message
                        self.print_message(sock, json_data)

                    else:
                        self.notify_error(sock, "json data of unfamiliar type", json_data)
                        continue

                    # after data processing successfully, propagated data in network
                    self.send_data(json_data)

                except KeyError as e:
                    self.notify_error(sock, f"data was not a valid BronzeChain message\n{e}", data)
                    continue

        except socket.timeout:
            print(f"\nNo data from {sock.getpeername()} received in the last 10 seconds. Closing connection.")

        # socket error (imported socket as *)
        except error or OSError as e:
            print(f"\nsocket error while receiving data from {sock.getpeername()}\n{e}")
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
        print(f"\nreceived transaction from {sock.getpeername()}:\n", transaction_json)
        self.add_transaction(transaction)
        return True

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
            miner = data["miner"]

        except Exception as e:
            # possible errors: data doesn't fit hello packet format / missing properties
            # / data doesn't fit type (e.g. RSAkey)
            self.notify_error(sock, f"data was not a valid hello packet\n{e}", hello_packet)
            traceback.print_exc()
            return False

        else:
            # update peer database
            print(f"\nreceived hello from {sock.getpeername()}:\n", hello_packet)
            self.update_peer(address, name, public_key, miner)

            # send back hello if requested
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

    def main_loop(self):
        """main loop of action"""
        receive_thread = threading.Thread(target= self.receive_data)
        receive_thread.daemon = True
        receive_thread.start()

