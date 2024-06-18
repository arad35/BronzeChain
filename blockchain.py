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
import ast
import sqlite3 as lite
from blockchain_classes import *


class PacketHandlingError(Exception):
    pass


def address_string_to_tuple(address_string):
    """Convert an address string of the format 'address:port' to a tuple (address, port)"""
    address, port = address_string.split('_')
    return address, int(port)


def address_tuple_to_string(address_tuple):
    """Convert a tuple (address, port) to an address string of the format 'address:port'"""
    return f"{address_tuple[0]}_{address_tuple[1]}"


class Peer:
    """Represents a peer in the blockchain network"""

    def __init__(self, name, server_address, balance=50, miner=False, hop_max=3, time_to_live=240,
                 min_transactions=3, max_transactions=5, difficulty=2, reward=5):
        # initialize networking properties
        ip = gethostbyname(gethostname())
        self.connect_sock = socket(AF_INET, SOCK_STREAM)
        self.connect_sock.bind((ip, 0))
        self.address = self.connect_sock.getsockname()

        self.server_address = server_address
        self.server_sock = socket(AF_INET, SOCK_STREAM)

        self.send_sock = socket(AF_INET, SOCK_STREAM)
        # cache containing recent packet (hash: timestamp format)
        self.packet_cache = dict()

        # net constants
        self.hop_max = hop_max
        self.time_to_live = time_to_live

        # identifying properties
        self.name = name
        self.balance = balance
        self._private_key = RSA.generate(1024)
        self.public_key = self._private_key.public_key()

        # blockchain properties
        self.blockchain = Blockchain(min_transactions, max_transactions, difficulty, reward)
        self.miner = miner  # flag indicating whether peer is a miner
        self.peer_database: lite.Connection = None
        self.database_path = f"blockchain_{name}.db"

    @property
    def identity(self):
        """hexadecimal representation of public key"""
        return binascii.hexlify(self.public_key.export_key()).decode()

    @property
    def signer(self):
        """returns signer object of the peer"""
        return PKCS1_v1_5.new(self._private_key)

    @property
    def verified_transactions(self):
        """returns list of verified transactions"""
        return self.blockchain.verified_transactions

    @verified_transactions.setter
    def verified_transactions(self, value):
        """set verified transactions list"""
        self.blockchain.verified_transactions = value

    def create_peer_database(self):
        """"Create peer database"""
        try:
            conn = lite.connect(self.database_path, check_same_thread=False)
        except lite.Error as e:
            print(f"error creating peer database: {e}")
            return

        self.peer_database = conn
        cursor = conn.cursor()
        # address, name and public key are unique
        cursor.execute("DROP TABLE IF EXISTS Peers")
        cursor.execute("""CREATE TABLE IF NOT EXISTS Peers
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       address TEXT Unique,
                       name TEXT Unique,
                       public_key TEXT Unique,
                       is_user BOOLEAN)""")

        conn.commit()
        print(f"create peer database at path {self.database_path}, table Peers")

    def update_peer(self, address, name, public_key: RSA.RsaKey, is_user=False):
        """update peer info in database"""
        cursor = self.peer_database.cursor()

        # convert address and public key to string
        public_key = binascii.hexlify(public_key.export_key()).decode()
        address = address_tuple_to_string(address)

        try:
            # check if peer already exists
            cursor.execute("SELECT id from Peers WHERE address=? OR name=? OR public_key=?",
                           (address, name, public_key))
            row = cursor.fetchone()

            # if exists, update row
            if row:
                cursor.execute("UPDATE Peers SET address = ?, name = ?, public_key = ? WHERE id = ?",
                               (address, name, public_key, row[0]))

            # else insert a new row
            else:
                cursor.execute("INSERT INTO Peers(address, name, public_key, is_user) VALUES(?,?,?,?)",
                               (address, name, public_key, is_user))

            self.peer_database.commit()
            print("\nupdated peer in database")
            print(f"address: {address}\n name: {name}\n public_key: {public_key}")

        except lite.InterfaceError as e:
            print(f"sql error: {e}\naddress: {address}\nname: {name}\npublic_key: {public_key}")

    def fetch_public_key(self, peer_name):
        """fetch public key of peer by name
        returns public key if found, false if not found"""
        cursor = self.peer_database.cursor()

        cursor.execute("SELECT public_key from Peers WHERE name=?", (peer_name, ))
        row = cursor.fetchone()

        # return public key if found
        # convert public key to RSA key
        if row: return RSA.import_key(binascii.unhexlify(row[0]))

        # return false if not found
        return False

    def fetch_name(self, public_key_str):
        """fetch name by string rep of public key
        returns name if found, false if not found"""
        cursor = self.peer_database.cursor()

        cursor.execute("SELECT name from Peers WHERE public_key=?", (public_key_str,))
        row = cursor.fetchone()

        # return name if found
        if row: return row[0]

        # return false if not found
        return False

    def peers_list(self):
        """returns list of peer adresses in database"""
        cursor = self.peer_database.cursor()
        cursor.execute("SELECT address from Peers WHERE public_key !=?", (self.identity, ))
        rows = cursor.fetchall()

        peers = [address_string_to_tuple(row[0]) for row in rows]
        print(f"peers: {peers}")
        return peers

    def compute_packet_hash(self, data):
        """compute hash of a packet accordingly to its type
        data: packet in json format"""
        dict_data = json.loads(data)

        if dict_data["type"] == "Message":
            # return hash of the error message contents + timestamp
            message = dict_data["message"]
            # replace original packet data in its hash
            data_hash = self.compute_packet_hash(json.dumps(dict_data["data"]))
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
        # add packet hash, time of addition
        self.packet_cache[packet_hash] = time.time()
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
        print("\nnew transaction created:\n", new_transaction)
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
        print("\nnew transaction added to verified transactions:\n", transaction)

    def send_to_server(self, data, data_type):
        """send data to server
        returns: True if data sent successfully, error message otherwise"""

        dict_data = json.loads(data)
        dict_data["type"] = data_type
        data = json.dumps(dict_data)
        try:
            self.server_sock.sendall(data.encode())
            print(f"\nsent {data_type} packet to server{self.server_address}:\n{data}")

        except OSError as e:
            print(f"error when sending {data_type} to server{self.server_address}:\n{e}")
            return f"error when sending {data_type} to server{self.server_address}:\n{e}"

        return True

    def receive_from_server(self):
        """receive data from server
        returns: True if successfully received and processed server_hello message,
        error message otherwise"""
        sock = self.server_sock
        result = False
        try:
            # receive data
            try:
                json_data = sock.recv(1024).decode()
                print(f"received from server {self.server_address}:\n{json_data}")

            # socket error (imported socket as *)
            except error or OSError as e:
                print(f"\nsocket error while receiving data from server {self.server_address}\n{e}")
                raise PacketHandlingError

            # handle empty string
            if json_data == "":
                print(f"\nempty data from server {self.server_address}")
                raise PacketHandlingError

            # load data
            try:
                data = json.loads(json_data)

            except Exception as e:
                raise PacketHandlingError(sock, f"data wasn't a valid json\n{e}", json_data)

            try:
                # process message
                if data["type"] == "Server_Hello":
                    # process hello message
                    result = self.handle_server_hello(json_data)
                    if isinstance(result, str):
                        raise PacketHandlingError(sock, result, json_data)

                elif data["type"] == "Message":
                    # return error message
                    return data["message"]
                    pass

                else:
                    raise PacketHandlingError(sock, "json data of unfamiliar type", json_data)

            except KeyError as e:
                raise PacketHandlingError(sock, f"data was not a valid Server_Hello message\n{e}", data)

        except PacketHandlingError as e:
            # unsuccessful processing
            if len(e.args) == 3:
                # notify error if needed
                self.notify_error(*e.args, server=True)

        finally:
            sock.close()
            if result is True:
                return True

    def handle_server_hello(self, hello_packet):
        """handles a server_hello packet
        hello_packet: hello packet (json string)
        returns: True if hello packet processed successfully, error message otherwise"""
        try:
            # load data
            data = json.loads(hello_packet)
            if not data["sub_type"] == "Response":
                return "server_hello packet wasn't a response"
            peer_data = data["peer"]

            if data["peer"] is None:
                # no peer to update
                return True

            address = address_string_to_tuple(peer_data["address"])
            name = peer_data["name"]
            public_key = RSA.import_key(binascii.unhexlify(peer_data["public_key"]))

        except Exception as e:
            # possible errors: data doesn't fit hello packet format / missing properties
            # / data doesn't fit type (e.g. RSAkey)
            return f"data was not a valid hello packet\n{e}"

        # update peer database
        self.update_peer(address, name, public_key)
        return True

    def connect_to_server(self):
        """connect and interact with server
        returns: True if connected to server successfully, error message otherwise"""
        sock = self.server_sock
        # craft server_hello packet
        dict_data = {"sub_type": "Request",
                     "peer": {"address": address_tuple_to_string(self.address), "name": self.name, "public_key": self.identity}}
        data = json.dumps(dict_data)

        try:
            sock.connect(self.server_address)

        except OSError as e:
            print(f"error when sending server_hello to {self.server_address}:\n{e}")
            return f"error when sending server_hello to {self.server_address}:\n{e}"

        # send server_hello request
        # result - True if processed successfully, error message else
        result1 = self.send_to_server(data, data_type="Server_Hello")
        if isinstance(result1, str):
            return result1

        # process server_hello response
        # result - True if processed successfully, error message else
        result2 = self.receive_from_server()
        if isinstance(result2, str):
            return result2

        elif result1 is True and result2 is True:
            return True

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
            data_type = dict_data["type"]

            if dict_data["hop_count"] == 0:
                print(f'\nmax hop count reached for {data_type}:\n', json_data)
            # decrease hop count
            dict_data["hop_count"] = dict_data["hop_count"] - 1

        data = json.dumps(dict_data)
        # send transaction to all peers
        for addr in self.peers_list():
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
        data = json.dumps({'address': address_tuple_to_string(self.address),
                           "name": self.name,
                           "public_key": self.identity,
                           "send_me_hello": send_me_hello})

        self.send_data(data, new_data=True, data_type="Hello")

    def notify_error(self, sock, message, data, server=False):
        """print and sends a new error message
        message: error message
        data: string data received from peer
        server: whether the recipient is server"""
        print(f"\nerror from {sock.getpeername()}:\n{message}\n{data}")

        data_with_message = json.dumps({"message": message, "data": data})
        if server:
            # send error message to server
            self.send_to_server(data_with_message, data_type="Message")
        else:
            # send error message to all peers
            self.send_data(data_with_message, new_data=True, data_type="Message")

    def receive_data(self):
        """thread for connecting and receiving data from other peers"""
        sock = self.connect_sock
        sock.listen(5)

        while True:
            receive_sock, _ = sock.accept()

            peer_thread = threading.Thread(target=self.receive_from_peer, args=(receive_sock,))
            peer_thread.daemon = True
            peer_thread.start()
            time.sleep(2)

    @staticmethod
    def recv_all(sock):
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

        result = False
        try:
            # receive data
            try:
                json_data = self.recv_all(sock).decode()
                print(f"received from {sock.getpeername()}:\n{json_data}")
            # socket error (imported socket as *)
            except error or OSError as e:
                print(f"\nsocket error while receiving data from {sock.getpeername()}\n{e}")
                raise PacketHandlingError

            if json_data == "":
                print(f"\nempty data from {sock.getpeername()}")
                raise PacketHandlingError
            # load data
            try:
                data = json.loads(json_data)

            except Exception as e:
                raise PacketHandlingError(sock, f"data wasn't a valid json\n{e}", json_data)

            # check if packet is already in cache
            if self.is_packet_in_cache(json_data):
                print("packet is already in cache\n", json_data)
                raise PacketHandlingError

            # check hop count
            if data["hop_count"] < 0:
                raise PacketHandlingError(sock, "hop count exceeded", json_data)

            try:
                # process message
                # return without propagating packet if processing was unsuccessful
                if data["type"] == "Transaction":
                    # process transaction
                    # result - True if processed successfully, error message else
                    result = self.handle_transaction(json_data)
                    if isinstance(result, str):
                        raise PacketHandlingError(sock, result, json_data)

                elif data["type"] == "Block":
                    # process block
                    # result - True if processed successfully, error message else
                    result = self.handle_block(json_data)
                    if isinstance(result, str):
                        raise PacketHandlingError(sock, result, json_data)

                elif data["type"] == "Hello":
                    # process hello message
                    # result - True if processed successfully, error message else
                    result = self.handle_hello(json_data)
                    if isinstance(result, str):
                        raise PacketHandlingError(sock, result, json_data)

                elif data["type"] == "Message":
                    # no need for special processing
                    pass

                else:
                    raise PacketHandlingError(sock, "json data of unfamiliar type", json_data)

            except KeyError as e:
                raise PacketHandlingError(sock, f"data was not a valid BronzeChain message\n{e}", data)

        except PacketHandlingError as e:
            # unsuccessful processing
            if len(e.args) == 3:
                # notify error if needed
                self.notify_error(*e.args)

        else:
            if result is True:
                # successful processing
                self.add_packet_to_cache(json_data)
                # propagate packet
                self.send_data(json_data)

        finally:
            sock.close()

    def handle_transaction(self, transaction_json):
        """handles a received transaction
        transaction_json: json data with the transaction
        returns: True if transaction processed successfully, error message otherwise"""
        # load transaction
        try:
            transaction = Transaction.from_json(transaction_json)
        except Exception as e:
            return f"data was not a valid transaction\n{e}"

        verification = self.verify_transaction(transaction)
        if isinstance(verification, str):
            # invalid transaction (wrong hash or signature)
            return verification

        elif verification is True:
            # valid transaction, add to verified transactions
            self.add_transaction(transaction)

            return True

    def handle_block(self, block_json):
        """handles a received block
        block_json: json data with the transaction
        returns: True if transaction processed successfully, error message otherwise"""
        # load block
        blockchain = self.blockchain
        try:
            block = Block.from_json(block_json)
        except Exception as e:
            return f"data was not a valid block\n{e}"

        verification = blockchain.verify_block(block, Peer.verify_transaction)
        if isinstance(verification, str):
            # invalid block
            return verification

        elif verification is True:
            # valid block, add to chain and execute the block
            blockchain.add_block_to_chain(block)
            self.execute_last_block()

            return True

    def handle_hello(self, hello_packet):
        """handles an hello packet
        hello_packet: hello packet (json string)
        returns: True if hello packet processed successfully, error message otherwise"""
        try:
            # load data
            data = json.loads(hello_packet)
            address = address_string_to_tuple(data["address"])
            name = data["name"]
            public_key = RSA.import_key(binascii.unhexlify(data["public_key"]))

        except Exception as e:
            # possible errors: data doesn't fit hello packet format / missing properties
            # / data doesn't fit type (e.g. RSAkey)
            return f"data was not a valid hello packet\n{e}"

        # update peer database
        self.update_peer(address, name, public_key)
        # send back hello if requested
        if data["send_me_hello"]:
            self.send_hello(send_me_hello=False)

        return True

    def execute_last_block(self):
        """execute the transactions in last block of the chain"""
        block = self.blockchain.get_last_block()

        # hashes of transactions in block
        block_transaction_hashes = list(map(lambda transaction: transaction.tx_hash, block.transactions))

        # filter verified transactions that are not in the block
        filtered_transactions = filter(lambda transaction: transaction.tx_hash not in block_transaction_hashes,
                                       self.verified_transactions)
        # update verified transactions
        self.verified_transactions = list(filtered_transactions)

        # filter transactions in which the peer is the receiver
        receiver_transactions = filter(lambda transaction: transaction.receiver == self.public_key,
                                       block.transactions)
        # add received amount from balance
        for transaction in receiver_transactions:
            self.balance += transaction.value

        # filter transactions in which the peer is the sender
        sender_transactions = filter(lambda transaction: transaction.sender == self.public_key,
                                     block.transactions)
        # remove sent amount from balance
        for transaction in sender_transactions:
            self.balance -= transaction.value

        # acquire reward if peer is the miner
        if block.miner == self.public_key:
            self.balance += block.reward

    def new_block(self):
        """if there are enough transactions,
        Create, mine, and send a new block"""
        blockchain = self.blockchain
        # if there aren't enough transactions, return
        if not blockchain.can_create_block():
            print(f"{len(self.verified_transactions)} is not enough transactions for mining")
            return
        block = blockchain.create_new_block()
        blockchain.mine_block(block, self.public_key)

        verification = blockchain.verify_block(block, Peer.verify_transaction)
        if verification is True:
            print("Block verified successfully")
            self.send_block(block)
            blockchain.add_block_to_chain(block)
            self.execute_last_block()
            print("Block sent, added to chain and executed")

        else:
            print(f"Block verification failed: {verification}")
            print(f"Block details: {block}")

    def miner_thread(self):
        """Mine if peer is a miner"""
        while True:
            if self.miner:
                self.new_block()
            time.sleep(10)

    def cleanup(self):
        """clear expired packets"""

        while True:
            now_time = time.time()
            try:
                expired_packets = list(filter(lambda packet_hash:
                                              now_time - self.packet_cache[packet_hash] >= self.time_to_live,
                                              self.packet_cache.keys()))

                for packet in expired_packets:
                    add_time = self.packet_cache.pop(packet)
                    print(f"removed packet: {packet} at {now_time - add_time} seconds")

            except RuntimeError as e:
                print(f"error when going through packet cache: {e}")
                traceback.print_exc()
                continue

            time.sleep(10)

    def start(self):
        """start BronzeChain
        returns: True if started the peer successfully, error message otherwise"""

        # initialize database
        self.create_peer_database()
        self.update_peer(self.address, self.name, self.public_key, is_user=True)

        # connect to server
        result = self.connect_to_server()
        if isinstance(result, str):
            # unsuccessful connection
            return result

        elif result is True:
            # peer discovery
            send_hello_thread = threading.Thread(target=self.send_hello, args=(True, ))
            send_hello_thread.start()

            # start receive thread
            receive_thread = threading.Thread(target=self.receive_data)
            receive_thread.start()

            # start cleanup thread
            cleanup_thread = threading.Thread(target=self.cleanup)
            cleanup_thread.daemon = True
            cleanup_thread.start()

            # start mining thread
            miner_thread = threading.Thread(target=self.miner_thread)
            miner_thread.daemon = True
            miner_thread.start()

            return True


