import signal
import curses
import bech32
import hashlib
import tempfile
import time
import random
import string
import json
import socket
import threading
import shutil
import sys
import os
import datetime

shutdown_flag = threading.Event()
# Funciones de utilidad

def debug_log(message):
    """ Escribe un mensaje de depuración en un archivo """
    with open("pytoken.debug", "a") as debug_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        debug_file.write(f"{timestamp} - {message}\n")

def sha256_hash(input_data):
    sha256 = hashlib.sha256()
    sha256.update(input_data.encode())
    return sha256.hexdigest()

def simple_bitcoin_mining_simulation(input_data, difficulty):
    nonce = 0
    target = '0' * difficulty
    while not interrupted:
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

class Node:
    def __init__(self, host, port, blockchain):
        self.host = host
        self.port = port
        self.peers = []  # Lista de otros nodos en la red
        self.server_socket = None
        self.client_sockets = []
        self.blockchain = blockchain
        self.is_synchronized = False  # Añadido: estado de sincronización
        self.threads = []  # Lista para mantener un seguimiento de los hilos

    def is_synchronized(self):
        # Implementación de la lógica de sincronización
        # Retorna True si el nodo está sincronizado, False en caso contrario
        # Aquí va la lógica específica
        return self._is_synchronized

    def synchronize_with_network(self):
        if not self.is_synchronized:
            debug_log("Iniciando sincronización con la red...")
            # Aquí va el código para obtener los bloques faltantes
            # Por ejemplo, podrías enviar una solicitud a tus peers
            self.request_missing_blocks()
            # Después de recibir y verificar los bloques, actualiza el estado
            self.is_synchronized = True
            debug_log("Sincronización completada.")

    def request_missing_blocks(self):
        # Implementa la lógica para solicitar y recibir bloques faltantes
        for peer_socket in self.client_sockets:
            peer_socket.send("Request for missing blocks".encode('utf-8'))
            # Aquí deberías esperar y procesar la respuesta

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Node listening on {self.host}:{self.port}")
        threading.Thread(target=self.accept_connections).start()

    def accept_connections(self):
        while not shutdown_flag.is_set() and not interrupted:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            self.client_sockets.append(client_socket)
            new_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            new_thread.start()
            self.threads.append(new_thread)  # Añadir el hilo a la lista

    def handle_client(self, client_socket, addr):
        while not shutdown_flag.is_set() and not interrupted:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    print(f"Received message from {addr}: {message}")
                    # Aquí puedes agregar lógica para manejar los mensajes
            except:
                # Manejar la desconexión del cliente
                print(f"Disconnected from {addr}")
                self.client_sockets.remove(client_socket)
                break

    def connect_to_peer(self, peer_host, peer_port):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_host, peer_port))
            self.client_sockets.append(peer_socket)
            print(f"Connected to peer {peer_host}:{peer_port}")
            debug_log(f"Conectado al nodo {peer_host}:{peer_port}")
        except ConnectionRefusedError:
            debug_log(f"Error de conexión con {peer_host}:{peer_port}")
            print(f"Connection to {peer_host}:{peer_port} refused. Is the peer node running?")

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
            import tempfile
            import shutil
            temp_fd, temp_path = tempfile.mkstemp()
            with os.fdopen(temp_fd, 'w') as temp_file:
                json.dump(data, temp_file, indent=4)
            shutil.move(temp_path, self.filename)
        except Exception as e:
            print(f"Error al guardar en el archivo {self.filename}: {e}")
            debug_log(f"Error: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)

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

    def to_dict(self):
        # Convierte el objeto PyTokenBlockchain a un diccionario
        return {
            "wallets": {addr: wallet.to_dict() for addr, wallet in self.wallets.items()},
            "total_mined": PyTokenBlockchain.total_mined,
            "block_count": self.block_count,
            "last_hash": self.last_hash,
            "difficulty": self.difficulty,
            "blocks": self.blocks
        }

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
        try:
            data = {
                "wallets": {addr: wallet.to_dict() for addr, wallet in self.wallets.items()},
                "total_mined": PyTokenBlockchain.total_mined,
                "block_count": self.block_count,
                "last_hash": self.last_hash,
                "difficulty": self.difficulty,
                "blocks": self.blocks
            }
            file_manager.save(data)
            debug_log("Guardando estado de la blockchain")
        except Exception as e:
            debug_log(f"Error al guardar la blockchain: {e}")

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
            debug_log(f"Minando bloque {block_count}")

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
            mining_win.addstr(1, 1, f"Mining PyTokens - Block: {block_count}", curses.color_pair(1))
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

interrupted = False

def signal_handler(sig, frame):
    global interrupted
    if interrupted:
        return  # Evitar múltiples llamadas
    interrupted = True
    print("Guardando el estado y cerrando...")
    shutdown_flag.set()  # Indica a los hilos que deben detenerse
    try:
        file_manager.save(blockchain.to_dict())  # Guardar estado de la blockchain
    except Exception as e:
        print(f"Error al guardar la blockchain: {e}")
    finally:
        clean_up_resources()
        sys.exit(0)

def clean_up_resources():
    print("Cerrando recursos...")
    # Cerrar el socket del servidor
    if node.server_socket:
        node.server_socket.close()
    # Cerrar todos los sockets de cliente
    for client_socket in node.client_sockets:
        client_socket.close()
    # Esperar a que todos los hilos terminen
    for thread in node.threads:
        thread.join()

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

    # Verificar la sincronización antes de iniciar la minería
    if node.is_synchronized:
        print("Nodo sincronizado, iniciando minería...")
        try:
            while not shutdown_flag.is_set() and not interrupted:
                # Realizar minería dentro del bucle controlado por shutdown_flag
                miner.mine_block_with_curses(stdscr, mining_win, wallet_win, wallet_manager, blockchain.difficulty, 600, 10, file_manager)
        finally:
            # Asegurarse de que todos los recursos se cierren adecuadamente
            clean_up_resources()
    else:
        print("No se pudo sincronizar con la red. Verifique su conexión y reinicie el nodo.")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    host, port = 'localhost', 5000
    file_manager = BlockchainFileManager('pytoken_blockchain.json')
    blockchain = PyTokenBlockchain()
    blockchain.load_from_file(file_manager)
    node = Node(host, port, blockchain)
    node.start_server()
    node.connect_to_peer('localhost', 5000)
    node.synchronize_with_network()

    curses.wrapper(main)
