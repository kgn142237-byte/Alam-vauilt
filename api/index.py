from flask import Flask, request, jsonify
import requests
import json
import os
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

app = Flask(__name__)

URL = "https://client.ind.freefiremobile.com/GetBackpack"

BODY_HEX = "1a725b2c56ec52ba7d09623454c0a003"
BODY_BYTES = bytes.fromhex(BODY_HEX)

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def decrypt_aes_cbc(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    try:
        return unpad(cipher.decrypt(data), AES.block_size)
    except:
        return None

def decode_varint(data, offset):
    value = 0
    shift = 0

    while True:
        if offset >= len(data):
            raise ValueError("Truncated varint")

        b = data[offset]
        value |= (b & 0x7F) << shift
        offset += 1

        if not (b & 0x80):
            break

        shift += 7

    return value, offset

def parse_one_message(data, start):
    fields = []
    idx = start

    while idx < len(data):
        try:
            key, idx = decode_varint(data, idx)
        except:
            break

        field_num = key >> 3
        wire_type = key & 0x07

        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields.append({'num': field_num, 'type': 0, 'value': value, 'nested': None})

        elif wire_type == 1:
            value = int.from_bytes(data[idx:idx+8], 'little')
            idx += 8
            fields.append({'num': field_num, 'type': 1, 'value': value, 'nested': None})

        elif wire_type == 2:
            length, idx = decode_varint(data, idx)
            raw = data[idx:idx+length]
            idx += length

            nested = None

            try:
                nested, _ = parse_one_message(raw, 0)
            except:
                pass

            fields.append({'num': field_num, 'type': 2, 'value': raw, 'nested': nested})

        elif wire_type == 5:
            value = int.from_bytes(data[idx:idx+4], 'little')
            idx += 4
            fields.append({'num': field_num, 'type': 5, 'value': value, 'nested': None})

    return fields, idx

def collect_item_ids(fields):
    ids = []

    for f in fields:
        if f['num'] == 3 and f['type'] == 2 and f['nested'] is not None:
            for sub in f['nested']:
                if sub['num'] == 1 and sub['type'] == 0:
                    ids.append(sub['value'])

        if f['nested'] is not None:
            ids.extend(collect_item_ids(f['nested']))

    return ids

def load_item_database():
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_FILE = os.path.join(BASE_DIR, "data.json")

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        items = json.load(f)

    item_map = {}

    for item in items:
        iid = item.get("itemID")

        if iid is not None:
            item_map[iid] = item

    return item_map

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "usage": "/api?token=YOUR_JWT_TOKEN"
    })

@app.route("/api", methods=["GET"])
def api():

    token = request.args.get("token")

    if not token:
        return jsonify({
            "error": "Token required"
        }), 400

    headers = {
        "Host": "client.ind.freefiremobile.com",
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization": f"Bearer {token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1"
    }

    try:
        response = requests.post(
            URL,
            headers=headers,
            data=BODY_BYTES,
            timeout=15
        )

        if response.status_code != 200:
            return jsonify({
                "error": f"HTTP {response.status_code}"
            }), response.status_code

        raw = response.content

        plain = decrypt_aes_cbc(raw)

        if plain:
            data = plain
        else:
            data = raw

        fields, _ = parse_one_message(data, 0)

        ids = collect_item_ids(fields)

        item_map = load_item_database()

        grouped = defaultdict(list)

        for iid in ids:
            info = item_map.get(iid, {})

            item_type = info.get("type", "Unknown")

            grouped[item_type].append({
                "itemID": iid,
                "name": info.get("name", "Unknown"),
                "rare": info.get("Rare", ""),
                "icon": f"https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{iid}.png"
            })

        return jsonify({
            "status": "success",
            "total_items": len(ids),
            "categories": grouped
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
