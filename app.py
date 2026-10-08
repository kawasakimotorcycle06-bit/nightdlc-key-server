"""
nightdlc Telegram key server
----------------------------
Install:
    pip install flask requests

Set environment variables:
    TELEGRAM_BOT_TOKEN=8770432372:AAFmffdIZEBFEANDSQLlOPTemGrJqFp3k7Y
    ADMIN_IDS=7885956847
    PORT=8080

Run:
    python nightdlc_key_server.py

Endpoints:
    POST /api/verify
    POST /api/heartbeat   (optional)
    GET  /health

Telegram commands:
    /key              -> 7-day key
    /key 1d|7d|30d|lifetime
    /revoke KEY
    /reset KEY
    /keys
    /id
"""

import json
import os
import secrets
import string
import threading
import time
from pathlib import Path

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(x.strip()) for x in os.environ.get("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}
PORT = int(os.environ.get("PORT", "8080"))
DB_FILE = Path(os.environ.get("KEY_DB", "nightdlc_keys.json"))

db_lock = threading.Lock()


def load_db():
    if not DB_FILE.exists():
        return {"keys": {}, "telegram_links": {}}
    try:
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"keys": {}, "telegram_links": {}}


db = load_db()


def save_db():
    tmp = DB_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(DB_FILE)


def gen_key():
    alphabet = string.ascii_uppercase + string.digits
    parts = [
        "".join(secrets.choice(alphabet) for _ in range(4))
        for _ in range(3)
    ]
    return "NDLC-" + "-".join(parts)


def parse_duration(value):
    value = (value or "7d").lower()
    if value in ("life", "lifetime", "perm"):
        return None
    units = {"d": 86400, "h": 3600, "m": 60}
    try:
        n = int(value[:-1])
        unit = value[-1]
        if n <= 0 or unit not in units:
            return "bad"
        return int(time.time()) + n * units[unit]
    except Exception:
        return "bad"


def telegram_send(chat_id, text):
    if not BOT_TOKEN:
        return
    requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        json={"chat_id": chat_id, "text": text},
        timeout=10,
    )


def is_admin(chat_id):
    return chat_id in ADMIN_IDS


def create_key(telegram_id, duration="7d"):
    expires = parse_duration(duration)
    if expires == "bad":
        raise ValueError("bad duration")

    key = gen_key()
    db["keys"][key] = {
        "created": int(time.time()),
        "expires": expires,
        "telegram_id": int(telegram_id),
        "bound_user_id": None,
        "bound_client_id": None,
        "revoked": False,
    }
    db["telegram_links"][str(telegram_id)] = key
    save_db()
    return key, expires


@app.post("/api/verify")
def verify():
    body = request.get_json(silent=True) or {}
    key = str(body.get("key", "")).strip().upper()
    user_id = int(body.get("user_id", 0) or 0)
    client_id = str(body.get("client_id", ""))

    if not key:
        return jsonify(valid=False, message="missing key"), 400

    with db_lock:
        item = db["keys"].get(key)
        if not item:
            return jsonify(valid=False, message="invalid key"), 200

        if item.get("revoked"):
            return jsonify(valid=False, message="key revoked"), 200

        expires = item.get("expires")
        if expires is not None and int(expires) <= int(time.time()):
            return jsonify(valid=False, message="key expired"), 200

        # First successful verification binds the key to the Roblox user and
        # client. Subsequent checks must match both.
        if item.get("bound_user_id") is None:
            item["bound_user_id"] = user_id
            item["bound_client_id"] = client_id
            save_db()
        elif int(item.get("bound_user_id") or 0) != user_id:
            return jsonify(valid=False, message="key is bound to another user"), 200
        elif item.get("bound_client_id") and item["bound_client_id"] != client_id:
            return jsonify(valid=False, message="key is bound to another device"), 200

    return jsonify(valid=True, message="ok"), 200


@app.get("/health")
def health():
    return jsonify(ok=True, keys=len(db["keys"]))


def telegram_loop():
    if not BOT_TOKEN:
        print("TELEGRAM_BOT_TOKEN is not set; Telegram bot disabled.")
        return

    offset = 0
    print("Telegram bot polling started.")

    while True:
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                params={"timeout": 25, "offset": offset},
                timeout=35,
            )
            data = r.json()

            for update in data.get("result", []):
                offset = update["update_id"] + 1
                msg = update.get("message") or {}
                chat = msg.get("chat") or {}
                chat_id = chat.get("id")
                text = (msg.get("text") or "").strip()

                if not chat_id:
                    continue

                if text == "/id":
                    telegram_send(chat_id, f"Your Telegram ID: {chat_id}")
                    continue

                if text.startswith("/key"):
                    parts = text.split(maxsplit=1)
                    duration = parts[1] if len(parts) == 2 else "7d"

                    # Users can get one active key; admins can always generate.
                    old = db["telegram_links"].get(str(chat_id))
                    if old and not is_admin(chat_id):
                        item = db["keys"].get(old)
                        if item and not item.get("revoked"):
                            exp = item.get("expires")
                            if exp is None or exp > int(time.time()):
                                telegram_send(chat_id, f"Your existing key:\n{old}")
                                continue

                    try:
                        key, expires = create_key(chat_id, duration)
                    except ValueError:
                        telegram_send(chat_id, "Usage: /key 1d | 7d | 30d | lifetime")
                        continue

                    exp_text = "lifetime" if expires is None else time.strftime(
                        "%Y-%m-%d %H:%M UTC", time.gmtime(expires)
                    )
                    telegram_send(
                        chat_id,
                        f"Your nightdlc key:\n{key}\n\nExpires: {exp_text}",
                    )
                    continue

                if text.startswith("/revoke ") and is_admin(chat_id):
                    key = text.split(maxsplit=1)[1].strip().upper()
                    if key in db["keys"]:
                        db["keys"][key]["revoked"] = True
                        save_db()
                        telegram_send(chat_id, "Revoked.")
                    else:
                        telegram_send(chat_id, "Key not found.")
                    continue

                if text.startswith("/reset ") and is_admin(chat_id):
                    key = text.split(maxsplit=1)[1].strip().upper()
                    if key in db["keys"]:
                        db["keys"][key]["bound_user_id"] = None
                        db["keys"][key]["bound_client_id"] = None
                        save_db()
                        telegram_send(chat_id, "Device binding reset.")
                    else:
                        telegram_send(chat_id, "Key not found.")
                    continue

                if text == "/keys" and is_admin(chat_id):
                    active = sum(
                        1 for v in db["keys"].values()
                        if not v.get("revoked") and (
                            v.get("expires") is None or v["expires"] > int(time.time())
                        )
                    )
                    telegram_send(chat_id, f"Total keys: {len(db['keys'])}\nActive: {active}")
                    continue

                if text.startswith("/start"):
                    telegram_send(
                        chat_id,
                        "nightdlc key bot\n\n"
                        "/key - 7 day key\n"
                        "/key 1d - 1 day\n"
                        "/key 7d - 7 days\n"
                        "/key 30d - 30 days\n"
                        "/key lifetime - lifetime\n"
                        "/id - show Telegram ID"
                    )
        except Exception as exc:
            print("Telegram polling error:", exc)
            time.sleep(3)


if __name__ == "__main__":
    threading.Thread(target=telegram_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT)
