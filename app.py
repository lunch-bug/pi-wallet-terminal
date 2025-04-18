from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset, StrKey
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import threading, time, os

app = Flask(__name__, template_folder="templates")
CORS(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

wallet_locks = {}
thread_lock = threading.Lock()

HORIZON_URL = "https://api.mainnet.minepi.com"
NETWORK_PASSPHRASE = "Pi Mainnet"
server = Server(horizon_url=HORIZON_URL)

def get_keypair_from_mnemonic(mnemonic):
    try:
        seed = Bip39SeedGenerator(mnemonic).Generate()
        path = Bip44.FromSeed(seed, Bip44Coins.STELLAR).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        raw_key = path.PrivateKey().Raw().ToBytes()
        return Keypair.from_raw_ed25519_seed(raw_key)
    except Exception as e:
        raise ValueError("Mnemonic error: " + str(e))

def get_balances(public_key):
    try:
        account = server.load_account(public_key)
        for bal in account.balances:
            if bal.asset_type == "native":
                return float(bal.balance)
        return 0.0
    except Exception:
        return None

def get_wallet_lock(wallet):
    with thread_lock:
        if wallet not in wallet_locks:
            wallet_locks[wallet] = threading.Lock()
        return wallet_locks[wallet]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/transfer", methods=["POST"])
@limiter.limit("3/minute")
def transfer():
    try:
        data = request.get_json()
        passphrase = data.get("passphrase", "").strip()
        destination = data.get("destination", "").strip()
        amount = float(data.get("amount"))
        mode = data.get("mode", "")

        if not Mnemonic("english").check(passphrase):
            return jsonify({"status": "error", "message": "incorrect 24-word wallet passphrase"}), 400

        try:
            keypair = get_keypair_from_mnemonic(passphrase)
        except:
            return jsonify({"status": "error", "message": "incorrect 24-word wallet passphrase"}), 400

        public_key = keypair.public_key
        secret_key = keypair.secret

        if not StrKey.is_valid_ed25519_public_key(destination):
            return jsonify({"status": "error", "message": "incorrect receiver address"}), 400

        wallet_lock = get_wallet_lock(public_key)
        if not wallet_lock.acquire(blocking=False):
            return jsonify({"status": "error", "message": "wallet is busy, try again shortly"}), 429

        def process_transaction():
            try:
                if mode == "unlocked":
                    balance = get_balances(public_key)
                    if balance is None:
                        return jsonify({"status": "error", "message": "could not read balance"}), 500
                    if balance < amount:
                        return jsonify({"status": "error", "message": "insufficient Pi"}), 400
                    return send_transaction(public_key, secret_key, destination, amount)

                elif mode == "wait_locked":
                    start = time.time()
                    while time.time() - start <= 3600:
                        balance = get_balances(public_key)
                        if balance and balance >= amount:
                            return send_transaction(public_key, secret_key, destination, amount)
                        time.sleep(2)
                    return jsonify({"status": "error", "message": "bot timed out"}), 408

                return jsonify({"status": "error", "message": "invalid transfer mode"}), 400

            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": "system crashed please restart",
                    "debug": str(e)
                }), 500
            finally:
                wallet_lock.release()

        return process_transaction()

    except Exception as e:
        return jsonify({"status": "error", "message": "system crashed please restart", "debug": str(e)}), 500

@app.route("/check-balance", methods=["POST"])
def check_balance():
    try:
        passphrase = request.get_json().get("passphrase", "").strip()
        if not Mnemonic("english").check(passphrase):
            return jsonify({"status": "error", "message": "invalid passphrase"}), 400

        keypair = get_keypair_from_mnemonic(passphrase)
        public_key = keypair.public_key
        balance = get_balances(public_key)

        if balance is None:
            return jsonify({"status": "error", "message": "could not fetch balance"}), 500

        return jsonify({"status": "success", "balance": balance}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
