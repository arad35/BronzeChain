import socket

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
import sqlite3 as lite
DATABASE_PATH = "blockchain_peers.db"
PEER_DATABASE: lite.Connection = None


class PacketHandlingError(Exception):
    pass


def create_peer_database():
    """"Create peer database"""
    try:
        conn = lite.connect(DATABASE_PATH, check_same_thread=False)
    except lite.Error as e:
        print(f"error creating peer database: {e}")
        return

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
    print(f"create peer database at path {DATABASE_PATH}, table Peers")
    return conn


def update_peer(address, name, public_key: RSA.RsaKey, is_user=False):
    """add a peer to database
    returns: True if peer added successfully, error message otherwise"""
    cursor = PEER_DATABASE.cursor()

    # convert address and public key to string
    public_key = binascii.hexlify(public_key.export_key()).decode()
    address = str(address)

    try:
        # check if peer already exists
        cursor.execute("SELECT address from Peers WHERE address=?",
                       (address, ))
        row = cursor.fetchone()
        if row:
            return f"address {row[0]} already taken"

        cursor.execute("SELECT name from Peers WHERE name=?",
                       (name, ))
        row = cursor.fetchone()
        if row:
            return f"name {row[0]} already taken"

        cursor.execute("SELECT public_key from Peers WHERE public_key=?",
                       (public_key, ))
        row = cursor.fetchone()
        if row:
            return f"public_key {row[0]} already taken"

        # add peer to database
        cursor.execute("INSERT INTO Peers(address, name, public_key, is_user) VALUES(?,?,?,?)",
                       (address, name, public_key, is_user))

        PEER_DATABASE.commit()
        print("\nupdated peer in database")
        print(f"address: {address}\n name: {name}\n public_key: {public_key}")

    except lite.InterfaceError as e:
        print(f"sql error: {e}\naddress: {address}\nname: {name}\npublic_key: {public_key}")
        return f"server sql error: {e}"

    return True


def send_data(sock: SocketType, data, data_type):
    """send data to a peer"""
    dict_data = json.loads(data)
    dict_data["type"] = data_type
    data = json.dumps(dict_data)
    try:
        sock.sendall(data.encode())
        print(f"\nsent {data_type} packet to {sock.getpeername()}:\n{data}")

    except OSError as e:
        print(f"error when sending {data_type} to {sock.getpeername()}:\n{e}")


def send_hello(sock: SocketType, address):
    """sends server_hello packet to a requesting peer
    address: identifying address of requesting peer"""
    cursor = PEER_DATABASE.cursor()
    # convert address to string for query
    address = str(address)
    # fetch another random peer
    cursor.execute("SELECT address, name, public_key FROM Peers WHERE address != ? ORDER BY RANDOM() LIMIT 1", (address, ))
    row = cursor.fetchone()

    # craft server_hello packet
    dict_data = {"sub_type": "Response"}
    if not row:
        # requesting peer is the only peer in database
        dict_data["peer"] = None

    else:
        # add other peer to packet
        peer_dict = {'address': row[0],
                     "name": row[1],
                     "public_key": row[2]}
        dict_data["peer"] = peer_dict

    # send the packet
    data = json.dumps(dict_data)
    send_data(sock, data, data_type="Server_Hello")


def notify_error(sock: SocketType, message, data):
    """print and sends a new error message
    sock: socket to interact with
    message: error message
    data: string data received from peer"""
    print(f"\nerror from {sock.getpeername()}:\n{message}\n{data}")

    data_with_message = json.dumps({"message": message, "data": data})
    send_data(sock, data_with_message, "Message")


def handle_hello(sock: SocketType, hello_packet):
    """handles a server_hello packet
    hello_packet: hello packet (json string)
    returns: True if hello packet processed successfully, error message otherwise"""
    try:
        # load data
        data = json.loads(hello_packet)
        if not data["sub_type"] == "Request":
            return "server_hello packet wasn't a request"
        peer_data = data["peer"]
        address = peer_data["address"]
        print(f"peer address: {peer_data['address']}")
        print(f"peer address: {address}")
        name = peer_data["name"]
        public_key = RSA.import_key(binascii.unhexlify(peer_data["public_key"]))

    except Exception as e:
        # possible errors: data doesn't fit hello packet format / missing properties
        # / data doesn't fit type (e.g. RSAkey)
        return f"data was not a valid hello packet\n{e}"

    # update peer database
    result = update_peer(address, name, public_key)
    if isinstance(result, str):
        # address/name/key already taken
        return result

    elif result is True:
        # send server_hello response
        send_hello(sock, address)
        return True


def receive_from_peer(sock: SocketType):
    """thread for receiving data from another peer"""

    result = False
    try:
        # receive data
        try:
            json_data = sock.recv(1024).decode()
            print(f"received from {sock.getpeername()}:\n{json_data}")

        # socket error (imported socket as *)
        except error or OSError as e:
            print(f"\nsocket error while receiving data from {sock.getpeername()}\n{e}")
            raise PacketHandlingError

        # handle empty string
        if json_data == "":
            print(f"\nempty data from {sock.getpeername()}")
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
                # result - True if processed successfully, error message else
                result = handle_hello(sock, json_data)
                if isinstance(result, str):
                    raise PacketHandlingError(sock, result, json_data)

            elif data["type"] == "Message":
                # no need for special processing
                pass

            else:
                raise PacketHandlingError(sock, "json data of unfamiliar type", json_data)

        except KeyError as e:
            raise PacketHandlingError(sock, f"data was not a valid Server_Hello message\n{e}", data)

    except PacketHandlingError as e:
        # unsuccessful processing
        if len(e.args) == 3:
            # notify error if needed
            notify_error(*e.args)

    finally:
        sock.close()


def receive_connections(sock: SocketType):
    """thread for connecting peers"""
    # publish server address
    ip = gethostbyname(gethostname())
    sock.bind((ip, 0))
    print(f"server address: {sock.getsockname()}")
    sock.listen(5)

    while True:
        receive_sock, _ = sock.accept()
        pass
        print(f"new connection from {receive_sock.getpeername()}")

        peer_thread = threading.Thread(target=receive_from_peer, args=(receive_sock,))
        peer_thread.daemon = True
        peer_thread.start()
        time.sleep(2)


def main():
    # initialize database
    global PEER_DATABASE
    PEER_DATABASE = create_peer_database()
    connect_sock = socket(AF_INET, SOCK_STREAM)

    # start receive thread
    receive_thread = threading.Thread(target=receive_connections, args=(connect_sock, ))
    receive_thread.start()


if __name__ == "__main__":
    main()


