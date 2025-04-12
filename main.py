import os
import json
from dotenv import load_dotenv

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineReceiver
import hashlib
import binascii
import struct

load_dotenv(override=True)

class StratumProtocol(LineReceiver):
    def __init__(self):
        self.current_job = None
        self.extra_nonce = None
        self.difficulty = 1

    def connectionMade(self):
        print("[+] Conectado à pool. Autenticando...")
        # Envia subscription request
        self.sendLine(b'{"id": 1, "method": "mining.subscribe", "params": []}')
        # Envia autorização
        self.sendLine(
            b'{"id": 2, "method": "mining.authorize", "params": ["'
            + os.getenv('BITCOIN_ADDRESS').encode()
            + b'", "'
            + os.getenv('WORKER_PASSWORD').encode()
            + b'"]}'
        )

    def lineReceived(self, line):
        data = line.decode().strip()
        print(f"[Dados recebidos] {data}")

        try:
            msg = json.loads(data)
            method = msg.get("method")
            params = msg.get("params")

            # Recebeu um novo trabalho da pool
            if method == "mining.notify":
                self.current_job = {
                    "job_id": params[0],
                    "prev_hash": params[1],
                    "coinbase1": params[2],
                    "coinbase2": params[3],
                    "merkle_branch": params[4],
                    "version": params[5],
                    "nbits": params[6],
                    "ntime": params[7],
                    "clean_jobs": params[8],
                }
                self.extra_nonce = params[9] if len(params) > 9 else None
                self.start_mining()

            # Dificuldade ajustada
            elif method == "mining.set_difficulty":
                self.difficulty = params[0]

        except Exception as e:
            print(f"[ERRO] {e}")

    def start_mining(self):
        if not self.current_job:
            return

        print("[+] Iniciando mineração...")
        nonce = 0
        max_nonce = 1000000  # Limite para evitar loop infinito

        while nonce < max_nonce:
            # Monta o cabeçalho do bloco (simplificado)
            header = (
                struct.pack("<I", int(self.current_job["version"], 16)) +
                binascii.unhexlify(self.current_job["prev_hash"])[::-1] +
                binascii.unhexlify(self.calculate_merkle_root())[::-1] +
                struct.pack("<I", int(self.current_job["ntime"], 16)) +
                struct.pack("<I", int(self.current_job["nbits"], 16)) +
                struct.pack("<I", nonce)
            )

            # Calcula o hash SHA-256 duplo (como no Bitcoin)
            hash_result = hashlib.sha256(hashlib.sha256(header).digest()[::-1].hex())

            # Verifica se o hash atende à dificuldade
            if self.check_hash(hash_result):
                print(f"[+] Share encontrado! Nonce: {nonce}")
                self.submit_share(nonce, hash_result)
                break

            nonce += 1

    def calculate_merkle_root(self):
        # Simplificação: em um caso real, calcularíamos o Merkle Root das transações
        return self.current_job["merkle_branch"][0] if self.current_job["merkle_branch"] else "0" * 64

    def check_hash(self, hash_result):
        target = (1 << (256 - self.difficulty))  # Target simplificado
        hash_int = int(hash_result, 16)
        return hash_int < target

    def submit_share(self, nonce, hash_result):
        share_msg = {
            "params": [
                os.getenv('BITCOIN_ADDRESS'),
                self.current_job["job_id"],
                self.extra_nonce,
                self.current_job["ntime"],
                f"{nonce:08x}",
            ],
            "id": 3,
            "method": "mining.submit",
        }
        self.sendLine(json.dumps(share_msg).encode())

class StratumClientFactory(ReconnectingClientFactory):
    protocol = StratumProtocol

if __name__ == "__main__":
    print("[*] Conectando à pool Slush Pool...")
    reactor.connectTCP(os.getenv('POOL_HOST'), int(os.getenv('POOL_PORT')), StratumClientFactory())
    reactor.run()