import threading

import customtkinter as ctk
from blockchain import *
import re
import math

TIMEOUT = 15
HOP_MAX = 4
MIN_VALUE = 0.5
PEER = None


class SendTransactionError(Exception):
    pass


def start_blockchain(name, server_address, balance=50, miner=False):
    """start the BronzeChain application
    returns: the peer if peer added successfully, error message otherwise"""
    peer_obj = Peer(name, server_address, balance=balance, miner=miner)
    result = peer_obj.start()
    pass
    if isinstance(result, str):
        # couldn't start blockchain
        return result

    elif result is True:
        # send server_hello response
        return peer_obj


def replace_keys_with_names(data, peer: Peer):
    """use regex logic to replace public keys of peers with name"""
    pattern = re.compile(r'(sender|receiver|miner): (\w+)', re.IGNORECASE)

    def replace(match):
        if match.group(2) == peer.identity:
            # public key of the user, replace with username
            return f"{match.group(1)} : {peer.name}"

        # search for public key in database
        name = peer.fetch_name(match.group(2))
        if name: return f"{match.group(1)} : {name}" # found a name corresponding to key

        # return original string
        return match.group()

    return pattern.sub(replace, data)


def split_lines_long_string(string, line_length):
    """"split a long string into a multiline string"""
    lines = []

    lines_count = math.ceil(len(string) / line_length)
    index = 0
    for i in range(0, lines_count):
        if len(string[index:]) <= line_length:
           lines.append(string[index:])

        else:
            lines.append(string[index:index+line_length])
            index += line_length

    return '\n'.join(lines)


class ErrorTopLevel(ctk.CTkToplevel):
    def __init__(self, error: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        title = ctk.CTkLabel(self, text="Error", font=("Arial", 25))
        title.pack(padx=20, pady=(15, 0))
        message_label = ctk.CTkLabel(master=self, text=error, font=("Arial", 20))
        message_label.pack(padx=20, pady=15)


class RegistrationWindow(ctk.CTk):
    def __init__(self, server_address):
        super().__init__()
        self.title("BronzeChain")
        self.server_address = server_address

        self.error_window = None
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        title = ctk.CTkLabel(master=self, text="BronzeChain", font=("Arial", 25))
        sub_title = ctk.CTkLabel(master=self, text="Your decentralized digital wallet", font=("Arial", 15))

        title.grid(row=0, column=0, padx=20, pady=(20, 0), columnspan=2)
        sub_title.grid(row=1, column=0, padx=20, pady=(0, 10), columnspan=2)

        self.name = ctk.CTkEntry(master=self, placeholder_text="Register as:")
        self.join_button = ctk.CTkButton(master=self, text="Join", command=self.join_event)

        self.name.grid(row=2, column=0, padx=20, pady=(0, 20))
        self.join_button.grid(row=2, column=1, padx=(0, 20), pady=(0, 20))

    def join_event(self):
        global PEER
        username = self.name.get()
        if not username:
            self.display_error("You didn't enter a name")
            return

        uploading_label = ctk.CTkLabel(master=self, text="uploading application...", font=("Arial", 12))
        uploading_label.grid(row=3, column=0, padx=20, pady=(0, 10), columnspan=2)
        self.update()

        peer_obj = start_blockchain(username, self.server_address)

        if isinstance(peer_obj, str):
            # couldn't start blockchain
            self.display_error(peer_obj)

        elif isinstance(peer_obj, Peer):
            PEER = peer_obj
            self.destroy()

    def display_error(self, message):
        if self.error_window is None or not self.error_window.winfo_exists():
            self.error_window = ErrorTopLevel(master=self, error=message)
        else:
            self.error_window.focus()


class SideBar(ctk.CTkFrame):
    def __init__(self, master, peer_obj: Peer, **kwargs):
        super().__init__(master, **kwargs)
        self.peer = peer_obj

        self.name = ctk.CTkLabel(master=self, text=f"Name: {peer_obj.name}")
        self.balance = ctk.CTkLabel(master=self, text=f"Balance: {peer_obj.balance}")

        miner_var = ctk.StringVar(value="off")
        self.miner_switch = ctk.CTkSwitch(master=self, text="Miner", command=self.miner_toggle,
                                          variable=miner_var, onvalue="on", offvalue="off")

        self.name.grid(row=0, padx=10)
        self.balance.grid(row=1, padx=10)
        self.miner_switch.grid(row=2, padx=10)

    def miner_toggle(self):
        """turn miner mode on or off"""
        str_to_bool = {"on": True, "off": False}

        miner_mode_str = self.miner_switch.get()
        miner_mode = str_to_bool[miner_mode_str]
        self.peer.miner = miner_mode

    def update_balance(self, new_balance):
        """update the balance"""
        self.balance.configure(text=f"Balance: {new_balance}")


class SendTransactionFrame(ctk.CTkFrame):
    """Frame for sending transactions"""
    def __init__(self, master, peer_obj: Peer, **kwargs):
        super().__init__(master, **kwargs)
        self.peer = peer_obj
        self.time_pressed: time = None

        title = ctk.CTkLabel(master=self, text="Transfer BronzeCoin", font=("Arial", 36))
        title.grid(row=0, column=0, columnspan=2, pady=20, padx=20)

        self.receiver_entry = ctk.CTkEntry(master=self, placeholder_text="To: ", font=("Arial", 20))
        self.receiver_entry.grid(row=1, column=0, pady=(0, 20), sticky="w", padx=20)

        self.value_entry = ctk.CTkEntry(master=self, placeholder_text="Value: ", font=("Arial", 20))
        self.value_entry.grid(row=2, column=0, pady=(0, 20), sticky="w", padx=20)

        self.send_button = ctk.CTkButton(master=self, text="Send", font=("Arial", 20), command=self.send_transaction)
        self.send_button.grid(row=3, column=1, pady=(0, 20), sticky="e", padx=20)

        self.message_label = ctk.CTkLabel(master=self, text="", font=("Arial", 20))
        self.message_label.grid(row=4, column=0, sticky="w", columnspan=2, padx=20)

    def send_transaction(self):
        """create, verify and send a new transaction"""
        self.time_pressed = time.time()
        if self.message_label.cget("text") == "processing transaction...":
            return

        try:
            receiver_name = self.receiver_entry.get()
            if not receiver_name:
                raise SendTransactionError("You didn't enter receiver's name")

            if receiver_name == self.peer.name:
                raise SendTransactionError(f"You can't send a transaction to yourself, {self.peer.name}")

            receiver = self.peer.fetch_public_key(receiver_name)
            if not receiver:
                raise SendTransactionError(f"{receiver_name} not found in the peer database")

            value = self.value_entry.get()
            if not value:
                raise SendTransactionError(f"you didn't enter a value to transfer")

            try:
                value = float(value)
            except ValueError:
                raise SendTransactionError(f"{value} isn't a numeric value")

            if value > self.peer.balance:
                raise SendTransactionError(f"{value} is more then your balance {self.peer.balance}")

            if value < MIN_VALUE:
                raise SendTransactionError(f"{value} is less then the minimum transfer amount: {MIN_VALUE}")

            self.delete_entries()
            self.display_message("processing transaction...")

            # Create the transaction
            transaction = self.peer.create_transaction(receiver, value)

            # Verify the transaction
            verification = self.peer.verify_transaction(transaction)
            if verification is True:  # check if the verification is the boolean True (and not some string)
                self.display_message("Transaction verified successfully.")
                self.update()

                self.peer.send_transaction(transaction)
                self.peer.add_transaction(transaction)

                self.display_message("Transaction sent and added to verified transactions.")
                self.update()
            else:
                raise SendTransactionError(f"Transaction verification failed: {verification}")

        except SendTransactionError as e:
            self.delete_entries()
            self.display_message(e.args[0])
            self.update()

        finally:
            self.delete_message()

    def delete_entries(self):
        """delete receiver and value entries"""
        self.receiver_entry.delete(0, 'end')
        self.value_entry.delete(0, 'end')

    def display_message(self, message):
        """display a system message"""
        self.message_label.configure(text=message)

    def delete_message(self):
        time.sleep(3)
        if time.time() - self.time_pressed > 3:
            self.message_label.configure(text="")


class TransactionFrame(ctk.CTkFrame):
    """Frame of a single transaction"""
    def __init__(self, master, peer_obj, transaction: Transaction, transaction_number, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(fg_color="#0000FF")

        title = ctk.CTkLabel(master=self, text=f"Transaction #{transaction_number}", font=("Arial", 28))
        title.pack()
        transaction_data = json.loads(transaction.to_json())

        sender_label = ctk.CTkLabel(master=self,
                                    text=replace_keys_with_names(f"Sender: {transaction_data['sender']}", peer_obj),
                                    font=("Arial", 20))
        sender_label.pack(side='top', anchor='w', padx=10, pady=2)

        receiver_label = ctk.CTkLabel(master=self,
                                      text=replace_keys_with_names(f"Receiver: {transaction_data['receiver']}", peer_obj),
                                      font=("Arial", 20))
        receiver_label.pack(side='top', anchor='w', padx=10, pady=2)

        value_label = ctk.CTkLabel(master=self, text=f"Value: {transaction_data['value']}", font=("Arial", 20))
        value_label.pack(side='top', anchor='w', padx=10, pady=2)

        timestamp_label = ctk.CTkLabel(master=self,
                                       text=f"Timestamp: {transaction.timestamp.strftime('%m/%d/%Y, %H:%M:%S')}",
                                       font=("Arial", 20))
        timestamp_label.pack(side='top', anchor='w', padx=10, pady=2)

        tx_hash_label = ctk.CTkLabel(master=self, text=f"Tx_hash: {transaction_data['tx_hash']}",
                                     font=("Arial", 20))
        tx_hash_label.pack(side='top', anchor='w', padx=10, pady=2)

        signature_label = ctk.CTkLabel(master=self,
                                       text=split_lines_long_string(f"Signature: {transaction_data['signature']}", 100),
                                       font=("Arial", 20), justify="left")
        signature_label.pack(side='top', anchor='w', padx=10, pady=2)


class BlockTransactionsFrame(ctk.CTkScrollableFrame):
    """Frame of block transactions"""
    def __init__(self, master, peer_obj: Peer, block: Block, block_numer, **kwargs):
        super().__init__(master, **kwargs)

        i = 0
        for transaction in block.transactions:
            transaction_frame = TransactionFrame(self, peer_obj, transaction, i)
            transaction_frame.pack(pady=20)
            i += 1


class BlockTransactionsWindow(ctk.CTkToplevel):
    """Window of block transactions"""
    def __init__(self, master, peer_obj: Peer, block: Block, block_numer, **kwargs):
        super().__init__(master, **kwargs)
        # Get the screen width and height
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        # Set the geometry to full screen
        self.geometry(f"{screen_width}x{screen_height}")

        # Allow resizing
        self.resizable(True, True)

        title = ctk.CTkLabel(master=self, text=f"Block #{block_numer}: Transactions", font=("Arial", 36))
        title.pack(pady=20)

        transactions_frame = BlockTransactionsFrame(self, peer_obj, block, block_numer)
        transactions_frame.pack(side='top', anchor='w', padx=10, expand=True, fill=ctk.BOTH)


class BlockFrame(ctk.CTkFrame):
    """Frame of a single block"""
    def __init__(self, master, peer_obj, block: Block, block_number, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(fg_color="#0000FF")
        self.peer = peer_obj
        self.block = block
        self.block_number = block_number

        title = ctk.CTkLabel(master=self, text=f"Block#{block_number}", font=("Arial", 28))
        title.pack()
        block_data = json.loads(block.to_json())

        block_hash_label = ctk.CTkLabel(master=self, text=f"Block_hash: {block.compute_hash()}", font=("Arial", 20))
        block_hash_label.pack(side='top', anchor='w', padx=10, pady=2)

        tx_count_label = ctk.CTkLabel(master=self, text=f"Tx_count: {block_data['tx_count']}", font=("Arial", 20))
        tx_count_label.pack(side='top', anchor='w', padx=10, pady=2)

        tx_hash_root_label = ctk.CTkLabel(master=self, text=f"Tx_hash_root: {block_data['tx_hash_root']}",
                                          font=("Arial", 20))
        tx_hash_root_label.pack(side='top', anchor='w', padx=10, pady=2)

        difficulty_label = ctk.CTkLabel(master=self, text=f"Difficulty: {block_data['difficulty']}", font=("Arial", 20))
        difficulty_label.pack(side='top', anchor='w', padx=10, pady=2)

        reward_label = ctk.CTkLabel(master=self, text=f"Reward: {block_data['reward']}", font=("Arial", 20))
        reward_label.pack(side='top', anchor='w', padx=10, pady=2)

        previous_hash_label = ctk.CTkLabel(master=self, text=f"Previous_hash: {block_data['previous_hash']}",
                                           font=("Arial", 20))
        if previous_hash_label.cget("text") == "":
            previous_hash_label.configure(text='""')

        previous_hash_label.pack(side='top', anchor='w', padx=10, pady=2)

        nonce_label = ctk.CTkLabel(master=self, text=f"Nonce: {block_data['nonce']}", font=("Arial", 20))
        nonce_label.pack(side='top', anchor='w', padx=10, pady=2)

        miner_label = ctk.CTkLabel(master=self, text=replace_keys_with_names(f"Miner: {block_data['miner']}", peer_obj),
                                   font=("Arial", 20))
        miner_label.pack(side='top', anchor='w', padx=10, pady=2)

        timestamp_label = ctk.CTkLabel(master=self,
                                       text=f"Timestamp: {block.timestamp.strftime('%m/%d/%Y, %H:%M:%S')}",
                                       font=("Arial", 20))
        timestamp_label.pack(side='top', anchor='w', padx=10, pady=2)

        self.transactions_button = ctk.CTkButton(master=self, text="show transactions", font=("Arial", 20),
                                                 bg_color="#000000", command=self.show_transactions)
        self.transactions_button.pack(side="top", anchor="e", padx=10, pady=2)

        self.transaction_window = None

    def show_transactions(self):
        """show transactions list of a block"""
        # if transaction window not created yet, create it
        if self.transaction_window is None or not self.transaction_window.winfo_exists():
            self.transaction_window = BlockTransactionsWindow(self, self.peer, self.block, self.block_number)
            self.transaction_window.lift()
            self.transaction_window.attributes('-topmost', True)
            self.transaction_window.attributes('-topmost', False)
        else:
            self.transaction_window.lift()
            self.transaction_window.attributes('-topmost', True)
            self.transaction_window.attributes('-topmost', False)


class ScrollableBlockchainFrame(ctk.CTkScrollableFrame):
    """scrollable frame of blocks"""

    def __init__(self, master, peer_obj: Peer, **kwargs):
        super().__init__(master, **kwargs)
        self.peer = peer_obj

        self.block_frames = []

    def add_last_block(self):
        """add a block to the blockchain frame"""
        block_frame = BlockFrame(self, self.peer, self.peer.blockchain.get_last_block(), self.peer.blockchain.height)
        self.block_frames.append(block_frame)
        block_frame.pack(pady=20)


class LiveBlockchainFrame(ctk.CTkFrame):
    """view the live blockchain"""

    def __init__(self, master, peer_obj: Peer, **kwargs):
        super().__init__(master, **kwargs)
        self.peer = peer_obj

        title = ctk.CTkLabel(master=self, text=f"Live blockchain view", font=("Arial", 36))
        title.pack(side="top", pady=10)

        self.scrollable_frame = ScrollableBlockchainFrame(self, peer_obj)
        self.scrollable_frame.pack(side="top", fill="both", expand=True, pady=10)

    def add_last_block(self):
        """add a block to the scrollable frame"""
        self.scrollable_frame.add_last_block()


class Application(ctk.CTk):

    def __init__(self, peer_obj: Peer,*args, **kwargs):
        super().__init__(*args, **kwargs)
        self.peer = peer_obj
        # current amount of blocks
        self.height = self.peer.blockchain.height
        self.title("BronzeChain")

        self.peer = PEER
        self.sidebar = SideBar(self, peer_obj)
        self.sidebar.pack(side="left", fill="y", padx=10)

        self.send_frame = SendTransactionFrame(self, peer_obj)
        self.send_frame.pack(side="left", fill="y", padx=10, pady=10)

        self.blockchain_frame = LiveBlockchainFrame(self, peer_obj)
        self.blockchain_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # self.show_block()
        update_thread = threading.Thread(target=self.update_app)
        update_thread.daemon = True
        update_thread.start()

    def update_app(self):
        while True:
            if self.peer.blockchain.height > self.height:
                print(f"new block found")
                self.blockchain_frame.add_last_block()
                # self.process_last_block()
                self.sidebar.update_balance(self.peer.balance)
                self.height += 1
            time.sleep(3)


def run(server_address):
    """run the BronzeChain application"""
    global PEER
    ctk.set_default_color_theme('blue')
    ctk.set_appearance_mode('dark')

    registration_window = RegistrationWindow(server_address)
    registration_window.mainloop()

    app = Application(peer_obj=PEER)
    app.mainloop()



