import hashlib
texto = "olá"
for i in range(100):
    hash_sha256 = hashlib.sha256(texto.encode('utf-8')).hexdigest()
    print(hash_sha256)


from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import hashlib
import time
import struct

# Configuração do RPC (conexão com o bitcoind)
rpc_user = "seu_usuario"
rpc_password = "sua_senha"
rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@127.0.0.1:8332")

def mine_block():
    print("Iniciando mineração Bitcoin real...")
    
    # Passo 1: Pega um novo endereço para a recompensa
    wallet_address = rpc_connection.getnewaddress()
    print(f"Recompensa será enviada para: {wallet_address}")

    # Passo 2: Pega transações não confirmadas (mempool)
    tx_ids = rpc_connection.getrawmempool()
    raw_txs = [rpc_connection.getrawtransaction(tx_id) for tx_id in tx_ids]
    
    # Passo 3: Cria o bloco candidato
    block_template = rpc_connection.getblocktemplate()
    version = block_template["version"]
    previous_hash = block_template["previousblockhash"]
    timestamp = block_template["curtime"]
    bits = block_template["bits"]
    coinbase_tx = block_template["coinbasetxn"]["data"]

    # Passo 4: Calcula o Merkle Root (simplificado)
    tx_hashes = [hashlib.sha256(bytes.fromhex(tx)).digest() for tx in raw_txs]
    merkle_root = hashlib.sha256(hashlib.sha256(b''.join(tx_hashes)).digest())

    # Passo 5: Mineração (busca por um nonce válido)
    nonce = 0
    max_nonce = 100000000  # Limite para evitar loop infinito
    target = (1 << (256 - int(bits, 16)))  # Dificuldade atual
    
    print(f"Alvo (dificuldade): {target}")
    print("Começando a minerar... (Ctrl+C para parar)")

    while nonce < max_nonce:
        # Monta o cabeçalho do bloco
        header = (
            struct.pack("<L", version) +
            bytes.fromhex(previous_hash)[::-1] +
            merkle_root[::-1] +
            struct.pack("<LL", timestamp, int(bits, 16)) +
            struct.pack("<L", nonce)
        )

        # Calcula o hash do bloco
        block_hash = hashlib.sha256(hashlib.sha256(header)).digest()[::-1]
        hash_int = int.from_bytes(block_hash, byteorder='big')

        # Verifica se o hash é válido
        if hash_int < target:
            print(f"\nBloco minerado com sucesso! Nonce: {nonce}")
            print(f"Hash do bloco: {block_hash.hex()}")
            
            # Transmite o bloco para a rede
            block_hex = rpc_connection.submitblock(header.hex())
            if block_hex is None:
                print("Bloco aceito pela rede! Recompensa creditada.")
            else:
                print(f"Erro ao transmitir bloco: {block_hex}")
            
            return block_hash.hex()

        nonce += 1

    print("Fim das tentativas. Bloco não minerado.")
    return None

if __name__ == "__main__":
    mine_block()