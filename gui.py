import datetime
import customtkinter as ctk


class ErrorTopLevel(ctk.CTkToplevel):
    def __init__(self, error: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        label = ctk.CTkLabel(self, text="Sneaky error...", font=("Arial", 25))
        label.pack(padx=20, pady=(15, 0))
        error = ctk.CTkLabel(master=self, text=error, font=("Arial", 20))
        error.pack(padx=20, pady=15)


class BronzeChainRegistrationWindow(ctk.CTk):
    def __init__(self, on_join_callback):
        super().__init__()
        self.title("BronzeChain")

        self.error_window = None
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        title = ctk.CTkLabel(master=self,
                             text="BronzeChain",
                             font=("Arial", 25))
        sub_title = ctk.CTkLabel(master=self,
                                 text="Your decentralized digital wallet",
                                 font=("Arial", 15))

        title.grid(row=0, column=0, padx=20, pady=(20, 0), columnspan=2)
        sub_title.grid(row=1, column=0, padx=20, pady=(0, 10), columnspan=2)

        self.name = ctk.CTkEntry(master=self, placeholder_text="Register as:")
        self.join_button = ctk.CTkButton(master=self, text="Join", command=self.join_event)

        self.name.grid(row=2, column=0, padx=20, pady=(0, 20))
        self.join_button.grid(row=2, column=1, padx=(0, 20), pady=(0, 20))

        self.on_join_callback = on_join_callback

    def join_event(self):
        """Activated when the join_button is clicked."""
        client_name = self.name.get()
        if not client_name:
            self.display_error()
            return
        self.on_join_callback(self, client_name)

    def display_error(self):
        """Displays an error message regarding a name error."""
        error = "Please provide a valid name for the system."
        if self.error_window is None or not self.error_window.winfo_exists():
            self.error_window = ErrorTopLevel(master=self, error=error)
        else:
            self.error_window.focus()


class SideBar(ctk.CTkFrame):
    def __init__(self, client_name: str, balance: int, master, miner_callback, **kwargs):
        super().__init__(master, **kwargs)

        self.name = ctk.CTkLabel(master=self, text=f"Name: {client_name}")
        self.balance = ctk.CTkLabel(master=self, text=f"Balance: {balance}")

        miner_var = ctk.StringVar(value="on")
        self.miner_switch = ctk.CTkSwitch(master=self, text="Miner", command=miner_callback,
                                          variable=miner_var, onvalue="on", offvalue="off")

        self.name.grid(row=0)
        self.balance.grid(row=1)
        self.miner_switch.grid(row=2)


class Block(ctk.CTkFrame):
    def __init__(self,
                 title: str,
                 difficulty: int,
                 miner: str,
                 nonce: int,
                 previous_hash: str,
                 reward: int,
                 timestamp: datetime.datetime,
                 transaction_hash: str,
                 tx_count: int,
                 master,
                 **kwargs
                 ):
        super().__init__(master, **kwargs)

        self.configure(fg_color="#808080")

        title = ctk.CTkLabel(master=self, text=title, font=("Arial", 15))
        transaction_hash_label = ctk.CTkLabel(master=self, text=f"Transaction Hash: {transaction_hash}")
        previous_hash_label = ctk.CTkLabel(master=self, text=f"Previous Hash: {previous_hash}")
        diff_label = ctk.CTkLabel(master=self, text=f"Difficulty: {difficulty}")
        reward_label = ctk.CTkLabel(master=self, text=f"Reward: {reward}")
        nonce_label = ctk.CTkLabel(master=self, text=f"Nonce: {nonce}")
        miner_label = ctk.CTkLabel(master=self, text=f"Miner: {miner}")
        tx_count_label = ctk.CTkLabel(master=self, text=f"Transaction Count: {tx_count}")
        timestamp_label = ctk.CTkLabel(master=self, text=f"Timestamp: {timestamp}")

        title.pack(anchor='w')
        transaction_hash_label.pack(anchor='w')
        previous_hash_label.pack(anchor='w')
        diff_label.pack(anchor='w')
        reward_label.pack(anchor='w')
        nonce_label.pack(anchor='w')
        miner_label.pack(anchor='w')
        tx_count_label.pack(anchor='w')
        timestamp_label.pack(anchor='w')


class BlockChainFrame(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.__blocks = []

    def set_blocks(self, blocks):
        for block in self.__blocks:
            block.pack_forget()
        self.__blocks = blocks
        for i, block in enumerate(self.__blocks):
            block.pack(padx=10, pady=10, fill="x")


class TransactionCreationFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        label = ctk.CTkLabel(master=self, text="Transfer money with BronzeChain")
        label.grid(row=0, column=0, columnspan=3)

        self.to = ctk.CTkEntry(master=self, placeholder_text="To: ")
        self.value = ctk.CTkEntry(master=self, placeholder_text="Value: ")
        self.send_button = ctk.CTkButton(master=self, text="Send", command=self.send_event)

        self.to.grid(row=1, column=0, padx=20, pady=(0, 20))
        self.value.grid(row=1, column=1, padx=20, pady=(0, 20))
        self.send_button.grid(row=1, column=2, padx=(0, 20), pady=(0, 20))

    def send_event(self):
        """Called when the send button is clicked."""
        print("An event was sent!")
        self.to.delete(0, 'end')
        self.value.delete(0, 'end')


class Application(ctk.CTk):
    def __init__(self, client_name: str, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("BronzeChain")

        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        self.balance = 0
        self.sidebar = SideBar(client_name, 0, self, self.miner_toggle)
        self.sidebar.grid(row=0, column=0, sticky="ns", rowspan=3)

        self.tx_creation = TransactionCreationFrame(master=self)
        self.tx_creation.grid(row=0, column=1, sticky="news")

        self.blockchain = BlockChainFrame(master=self)
        ctk.CTkLabel(master=self, text="Live Blockchain").grid(row=1, column=1, columnspan=2, sticky="news")
        self.blockchain.grid(row=2, column=1, columnspan=2, sticky="news")

        self.blocks = [
            Block(
                master=self.blockchain,
                title="Block #100",
                difficulty=3,
                miner="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmZcXCBDxr4z...arORIlrbGpVUmoxn0eoW3hlpGKGzkc/8bQSwd0fAQIDAQAB",
                nonce=3734,
                previous_hash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                reward=1,
                timestamp=datetime.datetime.now(),
                transaction_hash="29c9b78e64b346a0977b004559617c4a389184f623159b28772d97dd47ba6fd5",
                tx_count=3,
            ),
            Block(
                master=self.blockchain,
                title="Block #99",
                difficulty=3,
                miner="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCX6JuQ/m0GPO...hL6mWZR1SPrFjgVXZzUdvD+0XB/WEQfe05ugOx2uwIDAQAB",
                nonce=8908,
                previous_hash="127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
                reward=1,
                timestamp=datetime.datetime.now(),
                transaction_hash="c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4",
                tx_count=3,
                )
        ]
        self.blockchain.set_blocks(self.blocks)

    def miner_toggle(self):
        print(f"{self.__class__} -> Miner Toggled.")


def start_main_application(register_window, client_name: str):
    register_window.destroy()
    app = Application(client_name)
    app.mainloop()


if __name__ == "__main__":
    registration_window = BronzeChainRegistrationWindow(start_main_application)
    registration_window.mainloop()
