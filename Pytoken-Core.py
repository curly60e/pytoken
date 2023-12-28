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
import shutil
import binascii
import logging
import configparser
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Configuración básica del logger
logging.basicConfig(filename='pytoken.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')
os.system('cls' if os.name == 'nt' else 'clear')

shutdown_flag = threading.Event()
# Funciones de utilidad

# Variables Globales
DEBUG_MODE = True  # Cambia a False para deshabilitar los logs de depuración

BLOCKCHAIN_MAIN_FILE = 'pytoken_blockchain.json'
BLOCKCHAIN_TEMP_FILE = 'pytoken_blockchain_temp.json'

def debug_log(message):
    if DEBUG_MODE:
        # Escribe un mensaje de depuración en un archivo
        with open("pytoken.debug", "a") as debug_file:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            debug_file.write(f"{timestamp} - {message}\n")

def save_peer_config(ip, port):
    config = configparser.ConfigParser()
    config['Peer'] = {'IP': ip, 'Port': port}
    with open('connections.conf', 'w') as configfile:
        config.write(configfile)

def load_peer_config():
    config = configparser.ConfigParser()
    config.read('connections.conf')
    return config['Peer']['IP'], int(config['Peer']['Port'])

def get_peer_info():
    try:
        return load_peer_config()
    except (KeyError, configparser.NoSectionError):
        # Solicitar IP y puerto si no se encuentra el archivo de configuración
        ip = input("Ingrese la dirección IP del par: ")
        port = input("Ingrese el puerto del par: ")
        save_peer_config(ip, port)
        return ip, int(port)

def sha256_hash(input_data):
    sha256 = hashlib.sha256()
    sha256.update(input_data.encode())
    return sha256.hexdigest()

def simple_bitcoin_mining_simulation(input_data, difficulty):
    nonce = 0
    target = '0' * difficulty
    while True:  # Elimina la verificación del tiempo
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

def send_json_with_delimiter(peer_socket, data_json):
    data_with_delimiter = data_json + DELIMITER
    peer_socket.sendall(data_with_delimiter.encode('utf-8'))

def receive_json_with_delimiter(peer_socket):
    data = ''
    while not data.endswith(DELIMITER):
        data += peer_socket.recv(1024).decode('utf-8')
    return data[:-len(DELIMITER)]

class Node:
    def __init__(self, host, port, blockchain, wallet_manager):
        self.host = host
        self.port = port
        self.peers = []  # Lista de otros nodos en la red
        self.server_socket = None
        self.client_sockets = []
        self.blockchain = blockchain
        self.is_synchronized = False  # Añadido: estado de sincronización
        self.threads = []  # Lista para mantener un seguimiento de los hilos
        self.wallet_manager = wallet_manager

    def check_synchronization(self):
        local_block_height = len(self.blockchain.blocks)
        for peer_socket in self.client_sockets:
            try:
                peer_socket.send(json.dumps({"action": "get_block_height"}).encode('utf-8'))
                response = peer_socket.recv(1024).decode('utf-8')
                response_data = json.loads(response)

                peer_block_height = response_data.get("block_height")
                if peer_block_height is not None and local_block_height < peer_block_height:
                    self.synchronize_with_network()
                    return False
            except Exception as e:
                debug_log(f"Error al sincronizar con el par: {e}")
        return True

    def download_blockchain(self, peer_socket):
        try:
            # Envía la solicitud
            send_json_with_delimiter(peer_socket, json.dumps({"action": "download_blockchain"}))
            response = receive_json_with_delimiter(peer_socket)
            blockchain_data = json.loads(response)
            # Procesar blockchain_data...
        except Exception as e:
            debug_log(f"Error al descargar la blockchain: {e}")

    def replace_chain(self, new_blocks):
        if self.is_valid_chain(new_blocks):
            self.blocks = new_blocks
            self.block_count = len(new_blocks)
            self.last_hash = new_blocks[-1]['hash']  # Asumiendo que cada bloque tiene un 'hash'
            debug_log("Blockchain reemplazada con éxito.")
        else:
            debug_log("Blockchain recibida no es válida.")

    def start_mining(self):
        """Prepara el minero y lo retorna."""
        #print("Preparando el proceso de minado...")
        return PyTokenMiner(self.blockchain, self.wallet_manager)

    def start_mining_process(self, stdscr):
        height, width = stdscr.getmaxyx()
        mining_win = curses.newwin(height // 2, width, 0, 0)
        wallet_win = curses.newwin(height // 2, width, height // 2, 0)

        self.miner.mine_block_with_curses(stdscr, mining_win, wallet_win, self.wallet_manager, self.blockchain.difficulty, 600, 10, file_manager, self)

    def synchronize_with_network(self):
        """
        Sincroniza el nodo con la red descargando la cadena de bloques más larga disponible.
        """
        #print("Iniciando la sincronización con la red...")
        longest_chain = None
        max_length = len(self.blockchain.blocks)

        for peer_socket in self.client_sockets:
            try:
                # Solicitar la longitud de la cadena de bloques del par
                peer_socket.send(json.dumps({"action": "get_block_height"}).encode('utf-8'))
                response = peer_socket.recv(1024).decode('utf-8')
                response_data = json.loads(response)
                peer_block_height = response_data.get("block_height")

                # Si el par tiene una cadena más larga, intentar descargarla
                if peer_block_height and peer_block_height > max_length:
                    print(f"Descargando cadena desde el par con altura de bloque {peer_block_height}")
                    peer_socket.send(json.dumps({"action": "download_blockchain"}).encode('utf-8'))
                    chain_response = peer_socket.recv(1024 * 1024).decode('utf-8')  # Ajusta el tamaño del buffer si es necesario
                    peer_chain = json.loads(chain_response)

                    # Verificar y actualizar si la cadena es válida y es la más larga hasta ahora
                    if self.blockchain.is_valid_chain(peer_chain['blocks']) and len(peer_chain['blocks']) > max_length:
                        max_length = len(peer_chain['blocks'])
                        longest_chain = peer_chain['blocks']

            except Exception as e:
                debug_log(f"Error synchronized to: {e}")

        # Reemplazar la cadena local si se encontró una cadena más larga válida
        if longest_chain:
            self.blockchain.replace_chain(longest_chain)
            self.file_manager.save_temp({"blocks": longest_chain})  # Guardar en el archivo temp.json
            debug_log("Updating to the longest blockchain.")
        else:
            debug_log("We have the longest blockchain.")

        print("Synchronization finished.")

        self.start_mining()

    def request_blockchain_info(self):
        for peer_socket in self.client_sockets:
            peer_socket.send(json.dumps({"action": "get_block_height"}).encode('utf-8'))
            response = peer_socket.recv(1024).decode('utf-8')
            response_data = json.loads(response)
            peer_block_height = response_data.get("block_height")

            if peer_block_height and peer_block_height > len(self.blockchain.blocks):
                self.download_blockchain(peer_socket)

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))  # Usar 'localhost'
        self.server_socket.listen(5)
        print(f"Node listening on localhost:{self.port}")
        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        while not shutdown_flag.is_set() and not interrupted:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            self.client_sockets.append(client_socket)
            new_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
            new_thread.start()
            self.threads.append(new_thread)  # Añadir el hilo a la lista

    def handle_client(self, client_socket, addr):
        while not shutdown_flag.is_set() and not interrupted:
            try:
                if message := client_socket.recv(1024).decode('utf-8'):
                    request = json.loads(message)
                    self.process_request(request, client_socket)
            except json.JSONDecodeError:
                print(f"Invalid message received from {addr}")
            except ConnectionResetError:
                print(f"Connection finish from {addr}")
                break
            except:
                print(f"Disconnected from {addr}")
                break

    def connect_to_peer(self, peer_host, peer_port):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_host, peer_port))
            self.client_sockets.append(peer_socket)
            print(f"Connected to peer {peer_host}:{peer_port}")
            debug_log(f"Connected to peer {peer_host}:{peer_port}")
        except Exception as e:
            debug_log(f"Connection failed to {peer_host}:{peer_port}: {e}")
            print(f"Connection to {peer_host}:{peer_port} refused.")

    def process_request(self, request, client_socket):
        action = request.get("action")
        if action == "get_block_height":
            response = {"block_height": len(self.blockchain.blocks)}
            client_socket.send(json.dumps(response).encode('utf-8'))
        elif action == "download_blockchain":
            blockchain_data = self.blockchain.to_dict()
            client_socket.send(json.dumps(blockchain_data).encode('utf-8'))
        # Agregar más acciones según sea necesario

# Clases de Blockchain
class WalletManager:
    def __init__(self, wallet_file):
        self.wallet_file = wallet_file
        self.wallets = {}
        self.transactions = []  # Lista de transacciones

    def create_wallet(self):
        # Generar un par de claves RSA
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Calcular una dirección única basada en la clave pública
        address = self.generate_wallet_address()

        # Guardar clave privada y dirección
        self.wallets[address] = {
            "address": address,
            "private_key": private_key.decode('utf-8'),  # Almacenar como string
            "public_key": public_key.decode('utf-8'),    # Almacenar también la clave pública
            "balance": 0
        }
        debug_log("Generating new address")
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

    def update_wallets_with_keys(self):
        for address, wallet_info in self.wallets.items():
            if 'private_key' not in wallet_info:
                # Generar un nuevo par de claves
                key = RSA.generate(2048)
                private_key = key.export_key()
                # Actualizar la wallet con la nueva clave privada
                wallet_info['private_key'] = private_key.decode('utf-8')
                debug_log("Generating privkey in the wallet")

        # Guardar las wallets actualizadas
        self.save_to_file()
        debug_log("Saving privkey in file")

    def generate_wallet_address(self):
        while True:
            # Generar un hash de clave pública (simplificado para el ejemplo)
            pubkey = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
            pubkey_hash = hashlib.sha256(pubkey.encode()).hexdigest()

            # Convertir el hash a 5 bits
            data = convert_bits(bytearray.fromhex(pubkey_hash), 8, 5)

            # Codificar en Bech32 con el prefijo personalizado 'pbc8sn'
            bech32_address = bech32.bech32_encode('pbc8sn', data)

            # Verificar si la dirección ya existe
            if bech32_address not in self.wallets:
                return bech32_address

class BlockchainFileManager:
    def __init__(self, main_file, temp_file):
        self.main_file = main_file
        self.temp_file = temp_file

    def load(self):
        # Cargar desde el archivo temporal primero
        if os.path.exists(self.temp_file):
            with open(self.temp_file, 'r') as file:
                return json.load(file)
        # Si no hay archivo temporal, cargar desde el archivo principal
        elif os.path.exists(self.main_file):
            with open(self.main_file, 'r') as file:
                return json.load(file)
        else:
            return None

    def save_temp(self, data):
        try:
            with open(self.temp_file, 'w') as temp_file:
                json.dump(data, temp_file, indent=4)
            debug_log("Saving new block on temp file")
        except Exception as e:
            debug_log(f"Error saving new mods in file {self.temp_file}: {e}")

    def save_final(self, data):
        try:
            with open(self.main_file, 'w') as file:  # Usar self.main_file
                json.dump(data, file, indent=4)
        except Exception as e:
            print(f"Error saving new mods in file {self.main_filename}: {e}")

class PyTokenBlockchain:
    MAX_TOKENS = 42_000_000
    total_mined = 0

    def __init__(self):
        self.wallets = {}  # Wallet addresses and their balances
        self.block_count = 0  # Contador de bloques
        self.blocks = []  # Lista para almacenar los bloques
        self.last_hash = ""   # Último hash de bloque minado
        self.difficulty = 5   # Dificultad inicia
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
        debug_log("Adding new block")

    def get_mining_reward(self):
        # Reduce a la mitad la recompensa cada 'halving_interval' bloques
        debug_log("Reduce a la mitad la recompensa")
        halvings = self.block_count // self.halving_interval
        return self.initial_reward / (2 ** halvings)

    def adjust_difficulty(self, total_mining_time, target_time_per_block, blocks_per_difficulty_adjustment):
        if total_mining_time > 0:
            new_difficulty = self.difficulty * (total_mining_time / (blocks_per_difficulty_adjustment * target_time_per_block))
            self.difficulty = max(1, round(new_difficulty))
            debug_log("Difficulty adjust")

    def save_to_file(self, file_manager, temp=False):
        """ Guarda el estado de la blockchain en el archivo especificado. """
        try:
            data = self.to_dict()
            if temp:
                file_manager.save_temp(data)  # Guardar en el archivo temporal
                debug_log("Saving state in temp file")
            else:
                file_manager.save_final(data)  # Guardar en el archivo final
                debug_log("Saving state in final file")
        except Exception as e:
            debug_log(f"Error saving blockchain: {e}")

    def load_from_file(self, file_manager):
        if data := file_manager.load():
            # Actualiza el estado de la blockchain con los datos cargados
            debug_log("Actualiza el estado de la blockchain con los datos cargados")
            self.wallets = {addr: PyTokenWallet.from_dict(wallet) for addr, wallet in data["wallets"].items()}
            PyTokenBlockchain.total_mined = data["total_mined"]
            self.block_count = data.get("block_count", 0)
            self.blocks = data.get("blocks", [])
            self.last_hash = data.get("last_hash", "")

            # Actualiza la dificultad basándose en el último bloque guardado
            debug_log("Actualiza la dificultad basándose en el último bloque guardado")
            if data["blocks"]:
                last_block = data["blocks"][-1]
                self.difficulty = last_block["difficulty"]
            else:
                self.difficulty = 1
            debug_log("Loading blockchain from final file")
        else:
            # Establecer valores predeterminados si no hay datos cargados
            debug_log("Establecer vaores predeterminados si no hay datos cargados")
            self.difficulty = 1
            self.blocks = []
            self.block_count = 0
            self.wallets = {}
            PyTokenBlockchain.total_mined = 0
            self.last_hash = ""

    def add_reward_to_wallet(self, wallet_manager, address, amount):
        if PyTokenBlockchain.total_mined + amount > PyTokenBlockchain.MAX_TOKENS:
            amount = PyTokenBlockchain.MAX_TOKENS - PyTokenBlockchain.total_mined
        wallet_manager.add_balance(address, amount)
        PyTokenBlockchain.total_mined += amount
        debug_log("Adding reward to wallet")

class PyTokenMiner:
    def __init__(self, blockchain, wallet_manager):
        self.blockchain = blockchain
        self.wallet_manager = wallet_manager
        self.wallet_address = self.wallet_manager.create_wallet()

    def mine_block_with_curses(self, stdscr, mining_win, wallet_win, wallet_manager, start_difficulty, target_time_per_block, blocks_per_difficulty_adjustment, file_manager, node, debug_info_win):
        debug_log("Iniciando método mine_block_with_curses")
        curses.curs_set(0)
        difficulty = start_difficulty
        block_times = []  # Lista para almacenar tiempos de minería de cada bloque
        # Obtener dimensiones de la pantalla
        debug_log("Obtener dimensiones de la pantalla")
        height, width = stdscr.getmaxyx()

        # Crear ventanas para minería y wallet
        debug_log("Crear ventanas para minería y wallet")
        mining_info_win = curses.newwin(height // 2, width // 2, 0, 0)
        node_info_win = curses.newwin(height // 2, width // 2, 0, width // 2)
        wallet_win = curses.newwin(height // 2, width, height // 2, 0)

        while PyTokenBlockchain.total_mined < PyTokenBlockchain.MAX_TOKENS and not shutdown_flag.is_set() and not interrupted:
            debug_log("Iniciando bucle while PyTokenBlockchain")
            start_time = time.time()
            block_count = self.blockchain.block_count

            # Minería de un bloque
            debug_log("Iniciando dentro del bucle while PyTokenBlockchain -Mineria de un bloque-")
            transactions = generate_fake_transactions(num_transactions=1)
            input_data = f"Block {block_count}: {transactions}"
            nonce, hash_result = simple_bitcoin_mining_simulation(input_data, difficulty)
            end_time = time.time()
            mining_time = end_time - start_time
            debug_log(f"Mining block {block_count}")

            # Minería y actualización de blockchain
            debug_log("Minería y actualización de blockchain")
            mining_reward = self.blockchain.get_mining_reward()
            self.blockchain.add_reward_to_wallet(self.wallet_manager, self.wallet_address, mining_reward)
            wallet_manager.save_to_file()
            self.blockchain.block_count += 1

            # Actualización de las ventanas
            debug_log("Iniciando dentro del bucle while PyTokenBlockchain -Actualización de las ventanas-")
            try:
                debug_log("Iniciando colores init_colors")
                init_colors()

                # Configuración de minería
                debug_log("Configuración de minería")
                difficulty = self.blockchain.difficulty
                total_mining_time = 0

                # Actualizar ventana de minería
                mining_info_win.clear()
                self.update_mining_window(mining_info_win, block_count, nonce, hash_result, difficulty, mining_time)
                mining_info_win.refresh()  # Marcar para refrescar, pero no refrescar aún

                # Actualizar ventana de información del nodo
                node_info_win.clear()
                self.update_node_info_window(node_info_win, height, width)
                node_info_win.refresh()  # Marcar para refrescar

                # Actualizar ventana de wallet
                wallet_win.clear()
                self.update_wallet_window(wallet_win, wallet_manager)
                wallet_win.refresh()  # Marcar para refrescar

                # Refrescar todas las ventanas a la vez
                curses.doupdate()

                # Añadir el bloque a la blockchain
                debug_log("Iniciando dentro del bucle while PyTokenBlockchain -Añadir el bloque a la blockchain-")
                debug_log("Añadir el bloque a la blockchain")
                script_pub_key = f"ScriptPubKey: {self.wallet_address}"
                script_sig = f"ScriptSig: {hashlib.sha256(str(nonce).encode() + self.wallet_address.encode()).hexdigest()[:10]}"
                block_info = {
                    "block_number": block_count,
                    "difficulty": difficulty,
                    "hash": hash_result,
                    "nonce": nonce,
                    "script_pub_key": script_pub_key,
                    "script_sig": script_sig
                }
                self.blockchain.add_block(block_info, difficulty)
                file_manager.save_temp(self.blockchain.to_dict())

                end_time = time.time()
                mining_time = end_time - start_time
                debug_log("Iniciando dentro del bucle while PyTokenBlockchain -Agregar tiempo de minería a la lista-")
                block_times.append(mining_time)  # Agregar tiempo de minería a la lista

                if len(block_times) == blocks_per_difficulty_adjustment:
                    average_mining_time = sum(block_times) / len(block_times)
                    difficulty = self.adjust_difficulty(average_mining_time, target_time_per_block)  # Cambio aquí
                    self.blockchain.difficulty = difficulty
                    debug_log("Iniciando dentro del bucle while PyTokenBlockchain -Reinicia la lista para el próximo intervalo-")
                    block_times.clear() # Reinicia la lista para el próximo intervalo

            except Exception as e:
                # Captura cualquier excepción durante la actualización de las ventanas
                debug_log(f"Error al actualizar ventanas: {e}")

    def update_node_info_window(self, debug_info_win, height, width):
        debug_info_win.clear()
        debug_info_win.box()

        try:
            with open("pytoken.debug", "r") as debug_file:
                lines = debug_file.readlines()
                # Mostrar tantas líneas como sea posible en la ventana
                debug_log("Mostrar tantas líneas como sea posible en la ventana")
                for i, line in enumerate(lines[-(height//3-2):], start=1):
                    debug_info_win.addstr(i, 1, line.strip(), curses.color_pair(1))
        except FileNotFoundError:
            debug_info_win.addstr(1, 1, "Archivo .debug no encontrado.", curses.color_pair(1))

        debug_info_win.refresh()

    def update_mining_window(self, mining_win, block_count, nonce, hash_result, difficulty, mining_time):
        # Obtener dimensiones de la ventana
        height, width = mining_win.getmaxyx()

        # Verificar si la ventana es lo suficientemente grande
        if height < 6 or width < 40:
            # No actualizar si la ventana es muy pequeña
            return

        # Limpiar y preparar la ventana
        mining_win.clear()
        mining_win.box()
        mining_win.addstr(1, 1, f"Mining PyTokens - Block: {block_count}", curses.color_pair(1))  # Rojo
        mining_win.addstr(2, 1, f"Nonce: {nonce}", curses.color_pair(2))  # Verde
        mining_win.addstr(3, 1, f"Hash: {hash_result}", curses.color_pair(3))  # Amarillo
        mining_win.addstr(4, 1, f"Difficulty: {difficulty}", curses.color_pair(4))  # Azul
        mining_win.addstr(5, 1, f"Time per Block: {mining_time:.2f} seconds", curses.color_pair(2))

        # Generar un Padding más extenso
        debug_log("Generar un Padding más extenso")
        padding_bits = ''.join([bin(random.randint(0, 255))[2:].rjust(8, '0') for _ in range(50)])
        padding_lines = [padding_bits[i:i+50] for i in range(0, len(padding_bits), 50)]

        mining_win.addstr(6, 1, "Padding:", curses.color_pair(1))

        # Mostrar Padding en múltiples líneas
        debug_log("Mostrar Padding en múltiples líneas")
        for idx, line in enumerate(padding_lines):
            mining_win.addstr(7 + idx, 1, line, curses.color_pair(2))

        mining_win.refresh()

    def update_wallet_window(self, wallet_win, wallet_manager):
        wallet_win.clear()
        wallet_win.box()

        total_balance = 0
        y = 1
        for address, wallet_info in wallet_manager.wallets.items():
            balance = wallet_info["balance"]
            total_balance += balance
            private_key_str = wallet_info.get('private_key', 'Not available')[:10] + "..." if 'private_key' in wallet_info else 'Not available'
            wallet_info_str = f"Address: {address}, Balance: {balance:.8f} PyTokens, Private Key: {private_key_str}"
            wallet_win.addstr(y, 1, wallet_info_str, curses.color_pair(1))
            y += 1

        wallet_win.addstr(y, 1, f"Total Balance: {total_balance:.8f} PyTokens", curses.color_pair(2))
        wallet_win.refresh()

    def adjust_difficulty(self, average_mining_time, target_time_per_block):
        if average_mining_time < target_time_per_block:
            return self.blockchain.difficulty + 1
        elif average_mining_time > target_time_per_block:
            return max(1, self.blockchain.difficulty - 1)
        return self.blockchain.difficulty


def init_colors():
    debug_log("Inicialización de colores")
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_BLUE, curses.COLOR_BLACK)

interrupted = False

def signal_handler(sig, frame):
    global interrupted
    if interrupted:
        return  # Evitar múltiples llamadas
    interrupted = True
    print("Saving final state and closing...")
    shutdown_flag.set()  # Indica a los hilos que deben detenerse
    try:
        blockchain.save_to_file(file_manager, temp=False)  # Guardar estado final en el archivo principal
    except Exception as e:
        print(f"Error saving blockchain: {e}")
    finally:
        clean_up_resources()
        sys.exit(0)


def clean_up_resources():
    print("Closing resources...")
    # Cerrar el socket del servidor
    debug_log("Cerrar el socket del servidor")
    if node.server_socket:
        print("Closing server socket...")
        node.server_socket.close()
    # Cerrar todos los sockets de cliente
    debug_log("Cerrar todos los sockets de cliente")
    for client_socket in node.client_sockets:
        client_socket.close()
    # Esperar a que todos los hilos terminen
    debug_log("Esperar a que todos los hilos terminen")
    for thread in node.threads:
        thread.join()

# Realizar operaciones de red y minería después de mostrar la interfaz gráfica
debug_log("Realizar operaciones de red y minería después de mostrar la interfaz gráfica")
def start_network_operations(stdscr, mining_win, wallet_win, log_win, ip, port, debug_info_win, blockchain, file_manager, wallet_manager, node):
    # Usar log_win para mostrar mensajes
    debug_log("Usar log_win para mostrar mensajes")
    messages = [
        "Node listening on localhost:5000",
        f"Intentando conectar con el par {ip}:{port}",
        "Sincronizando con la red...",
        "Sincronización completada.",
        "Preparando el proceso de minado...",
    ]

    for i, msg in enumerate(messages):
        log_win.addstr(i + 1, 1, msg)
        log_win.refresh()
        time.sleep(0.5)  # Pausa para efecto visual, puede omitirse

        if i == 1:
            try:
                node.connect_to_peer(ip, port)
            except ConnectionRefusedError:
                log_win.addstr(..., f"La conexión al par {ip}:{port} fue rechazada.")
                log_win.refresh()

        elif i == 2:
            debug_log("Simular sincronización")
            node.synchronize_with_network()

        elif i == 4:
            debug_log("Crear instancia del minero y simular inicio de minería")
            miner = node.start_mining()
            log_win.addstr(i + 2, 1, "Minería iniciada.")
            log_win.refresh()
            # Inicia el proceso de minería
            debug_log("Inicia el proceso de minería")
            miner.mine_block_with_curses(stdscr, mining_win, wallet_win, wallet_manager, blockchain.difficulty, 600, 10, file_manager, node, debug_info_win)
    log_win.refresh()

def main(stdscr, blockchain, file_manager, wallet_manager, node, ip, port):
    # Inicializar colores y configuraciones de curses
    debug_log("Inicailizar colores y configuracion de curses")
    init_colors()
    curses.curs_set(0)  # Ocultar el cursor
    stdscr.clear()      # Limpiar la pantalla

    # Crear las ventanas para log, wallet y debug
    debug_log("Creando ventanas, log, wallet y debug")
    height, width = stdscr.getmaxyx()
    log_win = curses.newwin(10, width, height - 10, 0)
    wallet_win = curses.newwin(height - 10, width, 0, 0)
    mining_win = curses.newwin(height - 10, width, 0, 0)
    debug_info_win = curses.newwin(height - 10, width, 0, 0)
    log_win.scrollok(True)
    wallet_win.scrollok(True)

    # Dibujar bordes y títulos para las ventanas
    debug_log("Dibujando bordes y títulos para las ventanas")
    log_win.box()
    wallet_win.box()
    log_win.addstr(0, 2, ' Log ')
    wallet_win.addstr(0, 2, ' Wallet ')

    # Refrescar las ventanas para mostrarlas
    debug_log("Refrescando ventanas para mostrarlas")
    stdscr.refresh()
    log_win.refresh()
    wallet_win.refresh()

    # Iniciar operaciones de red y minería en un hilo separado
    debug_log("Iniciando operaciones de red y minería en un hilo separado")
    network_thread = threading.Thread(target=start_network_operations, args=(stdscr, mining_win, wallet_win, log_win, ip, port, debug_info_win, blockchain, file_manager, wallet_manager, node), daemon=True)
    network_thread.start()

    # Mantener la interfaz gráfica activa mientras el hilo de red está en ejecución
    debug_log("Mantener la interfaz gráfica activa mientras el hilo de red está en ejecución")
    while network_thread.is_alive():
        wallet_win.refresh()
        time.sleep(0.01)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    # Obtener la IP y el puerto del par antes de iniciar curses
    debug_log("Obtener la IP y el puerto de par antes de iniciar curses")
    ip, port = get_peer_info()

    # Inicialización de las dependencias
    debug_log("Inicialización de las dependencias")
    blockchain = PyTokenBlockchain()
    file_manager = BlockchainFileManager('pytoken_blockchain.json', 'pytoken_blockchain_temp.json')
    wallet_manager = WalletManager('pytoken_wallet.json')
    node = Node('localhost', port, blockchain, wallet_manager)

    wallet_manager.load_from_file()
    wallet_manager.update_wallets_with_keys()

    # Iniciar curses pasando la instancia de node junto con ip y port a main
    debug_log("Iniciar curses pasando la instancia de node junto con ip y port a main")
    curses.wrapper(main, blockchain, file_manager, wallet_manager, node, ip, port)
