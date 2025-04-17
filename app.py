from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import threading
import time

app = Flask(__name__, template_folder="templates")  # Serve HTML from /templates
CORS(app)
limiter = Limiter(app, key_func=get_remote_address)

HORIZON_URL = "https://api.mainnet.minepi.com"
NETWORK_PASSPHRASE = "Pi Mainnet"
server = Server(horizon_url=HORIZON_URL)

wallet_locks = {}
thread_lock = threading.Lock()

# ----------------- Key Derivation -----------------
def get_keypair_from_mnemonic(mnemonic: str):
    try:
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.STELLAR) \
                         .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        private_key = bip44_ctx.PrivateKey().Raw().ToBytes()
        return Keypair.from_raw_ed25519_seed(private_key)
    except Exception as e:
        raise ValueError("Mnemonic to keypair conversion failed: " + str(e))

# ----------------- Balance Check -----------------
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

# ----------------- Wallet Locking -----------------
def get_wallet_lock(wallet):
    with thread_lock:
        if wallet not in wallet_locks:
            wallet_locks[wallet] = threading.Lock()
        return wallet_locks[wallet]

# ----------------- Serve Frontend -----------------
@app.route("/")
def index():
    return render_template("index.html")

# ----------------- Transfer Endpoint -----------------
@app.route("/transfer", methods=["POST"])
@limiter.limit("3/minute")
def transfer():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()
        destination = data.get("destination", "").strip()
        amount = float(data.get("amount"))
        mode = data.get("mode", "")

        mnemo = Mnemonic("english")
        if not mnemo.check(passphrase):
            return jsonify({"status": "error", "message": ">> wrong passphrase"}), 400

        try:
            keypair = get_keypair_from_mnemonic(passphrase)
        except Exception:
            return jsonify({"status": "error", "message": ">> error with public key"}), 400

        public_key = keypair.public_key
        secret_key = keypair.secret

        try:
            server.load_account(destination)
        except Exception:
            return jsonify({"status": "error", "message": ">> error with public key"}), 400

        wallet_lock = get_wallet_lock(public_key)
        if not wallet_lock.acquire(blocking=False):
            return jsonify({"status": "error", "message": ">> wallet is busy with another operation"}), 429

        def process_transaction():
            try:
                if mode == "unlocked":
                    available, _ = get_balances(public_key)
                    if available is None:
                        return jsonify({"status": "error", "message": ">> error with public key"}), 400
                    if available < amount:
                        return jsonify({"status": "error", "message": ">> insufficient Pi"}), 400
                    return send_transaction(public_key, secret_key, destination, amount)

                elif mode == "wait_locked":
                    start_time = time.time()
                    while time.time() - start_time <= 3600:
                        available, _ = get_balances(public_key)
                        if available is None:
                            return jsonify({"status": "error", "message": ">> error with public key"}), 400
                        if available >= amount:
                            return send_transaction(public_key, secret_key, destination, amount)
                    return jsonify({"status": "error", "message": ">> bot timed out"}), 408

                else:
                    return jsonify({"status": "error", "message": ">> invalid mode"}), 400

            except Exception as e:
                return jsonify({"status": "error", "message": ">> system crashed please restart", "debug": str(e)}), 500
            finally:
                wallet_lock.release()

        return process_transaction()

    except Exception as e:
        return jsonify({"status": "error", "message": ">> system crashed please restart", "debug": str(e)}), 500

# ----------------- Send Transaction -----------------
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
        return jsonify({"status": "success", "message": ">> transaction successful", "tx": response}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": ">> system crashed please restart", "debug": str(e)}), 500

# ----------------- Check Balance -----------------
@app.route("/check-balance", methods=["POST"])
def check_balance():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()

        mnemo = Mnemonic("english")
        if not mnemo.check(passphrase):
            return jsonify({"status": "error", "message": "Invalid passphrase"}), 400

        keypair = get_keypair_from_mnemonic(passphrase)
        public_key = keypair.public_key

        available, _ = get_balances(public_key)
        return jsonify({"status": "success", "balance": available}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ----------------- Run App -----------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
