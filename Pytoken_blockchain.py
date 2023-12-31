import signal
import curses
import bech32
import hashlib
import time
import random
import string
import json
import os

# Funciones de utilidad
def sha256_hash(input_data):
    sha256 = hashlib.sha256()
    sha256.update(input_data.encode())
    return sha256.hexdigest()

def simple_bitcoin_mining_simulation(input_data, difficulty):
    nonce = 0
    target = '0' * difficulty
    while True:
        data_nonce_combo = input_data + str(nonce)
        hash_result = hashlib.sha256(data_nonce_combo.encode()).hexdigest()
        if hash_result.startswith(target):
            return nonce, hash_result
        nonce += 1

def generate_fake_transactions(num_transactions=5):
    transactions = []
    for _ in range(num_transactions):
        sender = f"Sender{random.randint(1, 1000)}"
        receiver = f"Receiver{random.randint(1, 1000)}"
        amount = round(random.uniform(0.01, 1000.00), 2)
        transactions.append(f"{sender} -> {receiver}: ${amount}")
    return ' | '.join(transactions)

def convert_bits(data, from_bits, to_bits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None

    return ret

def generate_wallet_address():
    # Generar un hash de clave pública (simplificado para el ejemplo)
    pubkey = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
    pubkey_hash = hashlib.sha256(pubkey.encode()).hexdigest()

    # Convertir el hash a 5 bits
    data = convert_bits(bytearray.fromhex(pubkey_hash), 8, 5)

    # Codificar en Bech32 con el prefijo personalizado 'pbc8sn'
    bech32_address = bech32.bech32_encode('pbc8sn', data)
    return bech32_address

# Clases de Blockchain
class WalletManager:
    def __init__(self, wallet_file):
        self.wallet_file = wallet_file
        self.wallets = {}

    def create_wallet(self):
        address = generate_wallet_address()
        self.wallets[address] = {"address": address, "balance": 0}
        return address

    def add_balance(self, address, amount):
        if address in self.wallets:
            self.wallets[address]["balance"] += amount

    def save_to_file(self):
        with open(self.wallet_file, 'w') as file:
            json.dump(self.wallets, file, indent=4)

    def load_from_file(self):
        if os.path.exists(self.wallet_file):
            with open(self.wallet_file, 'r') as file:
                self.wallets = json.load(file)

class BlockchainFileManager:
    def __init__(self, filename):
        self.filename = filename

    def save(self, data):
        try:
            with open(self.filename, 'w') as file:
                json.dump(data, file, indent=4)
        except Exception as e:
            print(f"Error al guardar en el archivo {self.filename}: {e}")

    def load(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as file:
                return json.load(file)
        else:
            return None

class PyTokenBlockchain:
    MAX_TOKENS = 42_000_000
    total_mined = 0

    def __init__(self):
        self.wallets = {}  # Wallet addresses and their balances
        self.block_count = 0  # Contador de bloques
        self.blocks = []  # Lista para almacenar los bloques
        self.last_hash = ""   # Último hash de bloque minado
        self.difficulty = 1   # Dificultad inicia
        self.initial_reward = 4.5  # Recompensa inicial por bloque
        self.halving_interval = 4 * 365 * 144  # Cada 4 años en bloques

    def add_block(self, block_info, current_difficulty):
        block_info["difficulty"] = current_difficulty  # Añadir la dificultad actual al bloque
        self.blocks.append(block_info)

    def get_mining_reward(self):
        # Reduce a la mitad la recompensa cada 'halving_interval' bloques
        halvings = self.block_count // self.halving_interval
        return self.initial_reward / (2 ** halvings)

    def adjust_difficulty(self, total_mining_time, target_time_per_block, blocks_per_difficulty_adjustment):
        if total_mining_time > 0:
            new_difficulty = self.difficulty * (total_mining_time / (blocks_per_difficulty_adjustment * target_time_per_block))
            self.difficulty = max(1, round(new_difficulty))

    def save_to_file(self, file_manager):
        data = {
            "wallets": {addr: wallet.to_dict() for addr, wallet in self.wallets.items()},
            "total_mined": PyTokenBlockchain.total_mined,
            "block_count": self.block_count,
            "last_hash": self.last_hash,
            "difficulty": self.difficulty,
            "blocks": self.blocks
        }
        file_manager.save(data)

    def load_from_file(self, file_manager):
        data = file_manager.load()
        if data:
            # Actualiza el estado de la blockchain con los datos cargados
            self.wallets = {addr: PyTokenWallet.from_dict(wallet) for addr, wallet in data["wallets"].items()}
            PyTokenBlockchain.total_mined = data["total_mined"]
            self.block_count = data.get("block_count", 0)
            self.blocks = data.get("blocks", [])
            self.last_hash = data.get("last_hash", "")

            # Actualiza la dificultad basándose en el último bloque guardado
            if data["blocks"]:
                last_block = data["blocks"][-1]
                self.difficulty = last_block["difficulty"]
            else:
                self.difficulty = 1
        else:
            # Establecer valores predeterminados si no hay datos cargados
            self.difficulty = 1
            self.blocks = []
            self.block_count = 0
            self.wallets = {}
            PyTokenBlockchain.total_mined = 0
            self.last_hash = ""


    def create_wallet(self):
        address = generate_wallet_address()
        self.wallets[address] = PyTokenWallet(address)
        return address

    def add_reward_to_wallet(self, wallet_manager, address, amount):
        if PyTokenBlockchain.total_mined + amount > PyTokenBlockchain.MAX_TOKENS:
            amount = PyTokenBlockchain.MAX_TOKENS - PyTokenBlockchain.total_mined
        wallet_manager.add_balance(address, amount)
        PyTokenBlockchain.total_mined += amount

class PyTokenMiner:
    def __init__(self, blockchain, wallet_manager):
        self.blockchain = blockchain
        self.wallet_manager = wallet_manager
        self.wallet_address = self.wallet_manager.create_wallet()

    def mine_block_with_curses(self, stdscr, mining_win, wallet_win, wallet_manager, start_difficulty, target_time_per_block, blocks_per_difficulty_adjustment, blockchain_file):
        curses.curs_set(0)
        difficulty = start_difficulty
        total_mining_time = 0  # Agregar para rastrear el tiempo total de minería

        while PyTokenBlockchain.total_mined < PyTokenBlockchain.MAX_TOKENS:
            start_time = time.time()  # Definir start_time al comienzo de cada iteración
          # Usar block_count de la blockchain
            block_count = self.blockchain.block_count

            # Minería de un bloque
            transactions = generate_fake_transactions(num_transactions=1)
            input_data = f"Block {block_count}: {transactions}"
            nonce, hash_result = simple_bitcoin_mining_simulation(input_data, difficulty)
            end_time = time.time()
            mining_time = end_time - start_time

            # Obtener recompensa de minería actual
            mining_reward = self.blockchain.get_mining_reward()

            # Rastrear el tiempo total de minería de los últimos 2016 bloques
            total_mining_time += end_time - start_time

            # Usar hash del bloque y nonce para generar ScriptPubKey y ScriptSig
            script_pub_key = f"ScriptPubKey: {self.wallet_address}"
            script_sig = f"ScriptSig: {hashlib.sha256(str(nonce).encode() + self.wallet_address.encode()).hexdigest()[:10]}"

            # Crear la información del bloque
            block_info = {
                "block_number": self.blockchain.block_count,
                "difficulty": self.blockchain.difficulty,
                "hash": hash_result,
                "nonce": nonce,
                "script_pub_key": script_pub_key,
                "script_sig": script_sig
                # Agregar más información si es necesario
            }

            # Añadir el bloque a la blockchain incluyendo la dificultad actual
            self.blockchain.add_block(block_info, self.blockchain.difficulty)

            end_time = time.time()
            mining_time = end_time - start_time  # Usar start_time y end_time para calcular mining_time

            # Actualizar blockchain y guardar
            self.blockchain.add_reward_to_wallet(wallet_manager, self.wallet_address, mining_reward)
            wallet_manager.save_to_file()
            self.blockchain.block_count += 1

            # Generar un Padding más extenso
            padding_bits = ''.join([bin(random.randint(0, 255))[2:].rjust(8, '0') for _ in range(50)])
            padding_lines = [padding_bits[i:i+50] for i in range(0, len(padding_bits), 50)]

            # Actualizar la ventana de minería con la información
            mining_win.clear()
            mining_win.box()
            mining_win.addstr(1, 1, f"Mining of PyTokens - Block: {block_count}", curses.color_pair(1))
            mining_win.addstr(2, 1, f"Nonce: {nonce}", curses.color_pair(2))
            mining_win.addstr(3, 1, f"Hash: {hash_result}", curses.color_pair(2))
            mining_win.addstr(4, 1, f"Difficulty: {difficulty}", curses.color_pair(2))
            mining_win.addstr(5, 1, script_pub_key, curses.color_pair(2))
            mining_win.addstr(6, 1, script_sig, curses.color_pair(2))
            mining_win.addstr(7, 1, f"Time per Block: {mining_time:.2f} segundos", curses.color_pair(2))  # Línea añadida para el tiempo de minería
            mining_win.addstr(8, 1, "Padding:", curses.color_pair(2))

            # Mostrar Padding en múltiples líneas
            for idx, line in enumerate(padding_lines):
                mining_win.addstr(9 + idx, 1, line, curses.color_pair(2))  # Ajuste del índice para acomodar la nueva línea

            mining_win.refresh()


            # Actualizar la ventana de wallet con recuadros
            wallet_win.clear()
            wallet_win.box()
            balance = wallet_manager.wallets[self.wallet_address]["balance"]
            wallet_info = f"Wallet: {self.wallet_address}, Balance: {balance:.8f} PyTokens"
            wallet_win.addstr(1, 1, wallet_info, curses.color_pair(1))
            wallet_win.refresh()

            if block_count % blocks_per_difficulty_adjustment == 0:
                actual_time_per_block = mining_time / blocks_per_difficulty_adjustment
                if actual_time_per_block < target_time_per_block:
                    difficulty += 1
                elif actual_time_per_block > target_time_per_block:
                    difficulty = max(1, difficulty - 1)
                start_time = time.time()
                # Actualizar la dificultad en la blockchain
                self.blockchain.difficulty = difficulty

                # Guardar el estado actualizado de la blockchain
                self.blockchain.save_to_file(blockchain_file)

            time.sleep(1)  # Pequeña pausa para que la UI sea visible

def init_colors():
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        # Agrega más pares de colores según sea necesario

# Ejemplo de uso con curses
def signal_handler(sig, frame):
    print("Guardando el estado y cerrando...")
    file_manager.save(blockchain)  # Asegúrate de usar file_manager aquí
    sys.exit(0)

def main(stdscr):
    # Inicializar colores y configuraciones de curses
    init_colors()

    # Obtener dimensiones de la pantalla
    height, width = stdscr.getmaxyx()

    # Crear ventanas para minería y wallet
    mining_win = curses.newwin(height // 2, width, 0, 0)
    wallet_win = curses.newwin(height // 2, width, height // 2, 0)

    # Configuración de blockchain y manejo de archivos
    blockchain_file = 'pytoken_blockchain.json'
    wallet_file = 'pytoken_wallet.json'
    file_manager = BlockchainFileManager(blockchain_file)
    blockchain = PyTokenBlockchain()
    blockchain.load_from_file(file_manager)
    wallet_manager = WalletManager(wallet_file)
    wallet_manager.load_from_file()

    miner = PyTokenMiner(blockchain, wallet_manager)
    miner.mine_block_with_curses(stdscr, mining_win, wallet_win, wallet_manager, blockchain.difficulty, 600, 10, file_manager)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    curses.wrapper(main)
