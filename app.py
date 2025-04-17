from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset, StrKey
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import threading
import time
import os

app = Flask(__name__, template_folder="templates")
CORS(app)

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Stellar Public Mainnet (if you need Pi, change URL)
HORIZON_URL = "https://horizon.stellar.org"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
server = Server(horizon_url=HORIZON_URL)

wallet_locks = {}
thread_lock = threading.Lock()

# Derive keypair from mnemonic
def get_keypair_from_mnemonic(mnemonic: str):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.STELLAR) \
                     .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    private_key = bip44_ctx.PrivateKey().Raw().ToBytes()
    return Keypair.from_raw_ed25519_seed(private_key)

# Get wallet balance
def get_balances(public_key):
    try:
        account = server.load_account(public_key)
        available = 0.0
        for bal in account.balances:
            if bal.asset_type == "native":
                available = float(bal.balance)
        return available, None
    except Exception:
        return None, None

# Lock per wallet
def get_wallet_lock(wallet):
    with thread_lock:
        if wallet not in wallet_locks:
            wallet_locks[wallet] = threading.Lock()
        return wallet_locks[wallet]

# Validate Stellar address format
def is_valid_public_key(pk):
    try:
        return StrKey.is_valid_ed25519_public_key(pk)
    except Exception:
        return False

# Frontend page
@app.route("/")
def index():
    return render_template("index.html")

# Handle transfers
@app.route("/transfer", methods=["POST"])
@limiter.limit("3 per minute")
def transfer():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()
        destination = data.get("destination", "").strip()
        amount = float(data.get("amount"))
        mode = data.get("mode", "")

        # Validate mnemonic
        mnemo = Mnemonic("english")
        if not mnemo.check(passphrase):
            return jsonify({"status": "error", "message": "incorrect 24-word wallet passphrase"}), 400

        # Try to derive keypair from passphrase
        try:
            keypair = get_keypair_from_mnemonic(passphrase)
        except Exception:
            return jsonify({"status": "error", "message": "incorrect 24-word wallet passphrase"}), 400

        public_key = keypair.public_key
        secret_key = keypair.secret

        # Validate destination public key
        if not is_valid_public_key(destination):
            return jsonify({"status": "error", "message": "incorrect receiver address"}), 400

        # Lock this wallet
        wallet_lock = get_wallet_lock(public_key)
        if not wallet_lock.acquire(blocking=False):
            return jsonify({"status": "error", "message": "wallet is busy, try again shortly"}), 429

        # Process transaction logic
        def process_transaction():
            try:
                if mode == "unlocked":
                    available, _ = get_balances(public_key)
                    if available is None:
                        return jsonify({"status": "error", "message": "system crashed please restart"}), 500
                    if available < amount:
                        return jsonify({"status": "error", "message": "insufficient Pi"}), 400
                    return send_transaction(public_key, secret_key, destination, amount)

                elif mode == "wait_locked":
                    start_time = time.time()
                    while time.time() - start_time <= 3600:
                        available, _ = get_balances(public_key)
                        if available is None:
                            return jsonify({"status": "error", "message": "system crashed please restart"}), 500
                        if available >= amount:
                            return send_transaction(public_key, secret_key, destination, amount)
                        time.sleep(2)
                    return jsonify({"status": "error", "message": "bot timed out"}), 408

                else:
                    return jsonify({"status": "error", "message": "invalid mode"}), 400

            except Exception as e:
                print("CRASH DEBUG:", str(e))
                return jsonify({
                    "status": "error",
                    "message": "system crashed please restart",
                    "debug": str(e)
                }), 500
            finally:
                wallet_lock.release()

        return process_transaction()

    except Exception as e:
        print("CRASH DEBUG:", str(e))
        return jsonify({"status": "error", "message": "system crashed please restart", "debug": str(e)}), 500

# Send a Stellar transaction
def send_transaction(public_key, secret_key, destination, amount):
    try:
        account = server.load_account(public_key)
        tx = (
            TransactionBuilder(
                source_account=account,
                network_passphrase=NETWORK_PASSPHRASE,
                base_fee=100
            )
            .append_payment_op(destination=destination, amount=str(amount), asset=Asset.native())
            .set_timeout(60)
            .build()
        )
        tx.sign(secret_key)
        response = server.submit_transaction(tx)
        return jsonify({"status": "success", "message": "transaction successful", "tx": response}), 200
    except Exception as e:
        print("SEND TX ERROR:", str(e))
        return jsonify({"status": "error", "message": "system crashed please restart", "debug": str(e)}), 500

# Endpoint for balance checking
@app.route("/check-balance", methods=["POST"])
def check_balance():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()

        mnemo = Mnemonic("english")
        if not mnemo.check(passphrase):
            return jsonify({"status": "error", "message": "incorrect 24-word wallet passphrase"}), 400

        keypair = get_keypair_from_mnemonic(passphrase)
        public_key = keypair.public_key

        available, _ = get_balances(public_key)
        return jsonify({"status": "success", "balance": available}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Run server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
