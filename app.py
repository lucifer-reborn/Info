from flask import Flask, request, jsonify
from proto import FreeFire_pb2
import httpx
import asyncio
import base64
import json
import time
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
from typing import Tuple

app = Flask(__name__)

# --- Configurações principais
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"


# --- Utilitários de criptografia e conversão
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    ciphertext = aes.encrypt(padded_plaintext)
    return ciphertext


async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance


# --- Auth flow
async def getAccess_Token(account_payload):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account_payload + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=payload, headers=headers)
        data = response.json()
        return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt(uid: str, password: str) -> Tuple[str, str, str]:
    account_payload = f"uid={uid}&password={password}"
    access_token, open_id = await getAccess_Token(account_payload)
    json_data = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    })
    encoded_result = await json_to_proto(json_data, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=payload, headers=headers)
        message = json.loads(json_format.MessageToJson(
            decode_protobuf(response.content, FreeFire_pb2.LoginRes)
        ))

        # REMOVER 'Bearer ' SE EXISTIR
        token = message.get("token", "0").replace("Bearer ", "")
        region = message.get("lockRegion", "0")
        server_url = message.get("serverUrl", "0")
        return token, region, server_url


# --- Endpoint API
@app.route('/auth', methods=['GET'])
def auth():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Parâmetros 'uid' e 'password' são obrigatórios"}), 400

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        token, lock_region, server_url = loop.run_until_complete(create_jwt(uid, password))
        loop.close()

        return jsonify({
            "token": token,  # Já está SEM 'Bearer'
            "lock_region": lock_region,
            "server_url": server_url
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


# --- Rodar o servidor
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)
