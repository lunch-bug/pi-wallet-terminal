from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset, StrKey
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import threading
import time

app = Flask(__name__)
CORS(app)

# Updated limiter setup for flask-limiter 3.5.0
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

wallet_locks = {}
thread_lock = threading.Lock()

# Determine network server and passphrase
def get_server_and_passphrase(network: str):
    if network == "stellar":
        return Server("https://horizon.stellar.org"), "Public Global Stellar Network ; September 2015"
    else:
        return Server("https://api.mainnet.minepi.com"), "Pi Mainnet"

# Derive keypair from 24-word passphrase
def get_keypair_from_mnemonic(mnemonic: str):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.STELLAR).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    private_key = bip44_ctx.PrivateKey().Raw().ToBytes()
    return Keypair.from_raw_ed25519_seed(private_key)

# Lock per wallet address
def get_wallet_lock(wallet):
    with thread_lock:
        if wallet not in wallet_locks:
            wallet_locks[wallet] = threading.Lock()
        return wallet_locks[wallet]

# Get native balance
def get_balances(server, public_key):
    try:
        account = server.load_account(public_key)
        for bal in account.balances:
            if bal.asset_type == "native":
                return float(bal.balance)
        return 0.0
    except Exception:
        return None

@app.route("/")
def home():
    return "Pi/Stellar Wallet Transfer API is running."

# Transfer endpoint
@app.route("/transfer", methods=["POST"])
@limiter.limit("3 per minute")
def transfer():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()
        destination = data.get("destination", "").strip()
        amount = float(data.get("amount"))
        mode = data.get("mode", "unlocked")
        network = data.get("network", "pi").strip().lower()

        server, NETWORK_PASSPHRASE = get_server_and_passphrase(network)

        # Validate passphrase
        mnemo = Mnemonic("english")
        if not mnemo.check(passphrase):
            return jsonify({"status": "error", "message": "incorrect 24-word wallet passphrase"}), 400

        try:
            keypair = get_keypair_from_mnemonic(passphrase)
        except Exception:
            return jsonify({"status": "error", "message": "could not derive keypair"}), 400

        public_key = keypair.public_key
        secret_key = keypair.secret

        # Validate destination format
        if not StrKey.is_valid_ed25519_public_key(destination):
            return jsonify({"status": "error", "message": "incorrect receiver address"}), 400

        wallet_lock = get_wallet_lock(public_key)
        if not wallet_lock.acquire(blocking=False):
            return jsonify({"status": "error", "message": "wallet is busy with another operation"}), 429

        # Transaction logic
        def process_transaction():
            try:
                if mode == "unlocked":
                    balance = get_balances(server, public_key)
                    if balance is None:
                        return jsonify({"status": "error", "message": "wallet is not funded"}), 400
                    if balance < amount:
                        return jsonify({"status": "error", "message": "insufficient Pi"}), 400
                    return send_transaction(server, public_key, secret_key, destination, amount, NETWORK_PASSPHRASE)

                elif mode == "wait_locked":
                    start_time = time.time()
                    while time.time() - start_time <= 3600:
                        balance = get_balances(server, public_key)
                        if balance is not None and balance >= amount:
                            return send_transaction(server, public_key, secret_key, destination, amount, NETWORK_PASSPHRASE)
                        time.sleep(2)
                    return jsonify({"status": "error", "message": "bot timed out"}), 408

                else:
                    return jsonify({"status": "error", "message": "invalid transfer mode"}), 400

            finally:
                wallet_lock.release()

        return process_transaction()

    except Exception as e:
        return jsonify({"status": "error", "message": "system crashed please restart", "debug": str(e)}), 500

# Submit transaction
def send_transaction(server, public_key, secret_key, destination, amount, passphrase):
    try:
        account = server.load_account(public_key)
        tx = (
            TransactionBuilder(
                source_account=account,
                network_passphrase=passphrase,
                base_fee=100
            )
            .append_payment_op(destination=destination, amount=str(amount), asset=Asset.native())
            .set_timeout(60)
            .build()
        )
        tx.sign(secret_key)
        result = server.submit_transaction(tx)
        return jsonify({"status": "success", "message": "transaction successful", "tx": result}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "system crashed please restart", "debug": str(e)}), 500

# Check balance endpoint
@app.route("/check-balance", methods=["POST"])
def check_balance():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()
        network = data.get("network", "pi").strip().lower()

        server, _ = get_server_and_passphrase(network)

        mnemo = Mnemonic("english")
        if not mnemo.check(passphrase):
            return jsonify({"status": "error", "message": "invalid passphrase"}), 400

        keypair = get_keypair_from_mnemonic(passphrase)
        public_key = keypair.public_key

        balance = get_balances(server, public_key)
        return jsonify({"status": "success", "balance": balance}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
