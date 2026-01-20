import argparse
import base64
import binascii
import hashlib
import json
import os
import ssl
from dataclasses import dataclass

import paho.mqtt.client as mqtt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_SIZE = 16
DEFAULT_DEFENSE_HOST = "10.100.61.175"
DEFAULT_DEFENSE_PORT = 443
DEFAULT_DEFENSE_USER = "system"
DEFAULT_DEFENSE_PASSWORD = "Bsln@456"

current_def_topic = ""
current_def_payload = ""


@dataclass
class Config:
    defense_host: str
    defense_https_port: int
    defense_username: str
    defense_password: str


class RSAx:
    def __init__(self):
        self._private_key = None

    def generate_key_pair(self, bits):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
        )

    def get_public_key(self):
        if self._private_key is None:
            return None
        return self._private_key.public_key()

    def decrypt(self, ciphertext):
        if self._private_key is None:
            raise ValueError("missing private key")

        if isinstance(ciphertext, str):
            data = ciphertext.encode("utf-8")
        else:
            data = ciphertext

        try:
            decoded = base64.b64decode(data, validate=True)
            data = decoded
        except (binascii.Error, ValueError):
            pass

        return self._private_key.decrypt(data, padding.PKCS1v15())


class API:
    def __init__(self, host, port, token=""):
        self.host = host
        self.port = port
        self.token = token

    def _create_headers(self):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Subject-Token"] = self.token
        return headers

    def _create_url(self, path):
        return f"https://{self.host}:{self.port}{path}"

    def request(self, method, path, data):
        url = self._create_url(path)
        headers = self._create_headers()

        try:
            res = requests.request(
                method,
                url,
                json=data,
                headers=headers,
                timeout=8,
                verify=False,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"error on {method} request\n{exc}") from exc

        return res.status_code, res.content

    def post(self, path, data):
        return self.request("POST", path, data)


class EncData:
    def __init__(self):
        self.payload = {}
        self.res = {}

    def create_payload(self, _username):
        self.payload = {
            "userName": "system",
            "clientType": "WINPC_V2",
        }

    def set_res(self, data):
        try:
            self.res = json.loads(data)
        except json.JSONDecodeError:
            return


class Auth:
    def __init__(self):
        self.payload = {}
        self.res = {}
        self.signature = ""

    def create_payload(self, signature, username, random_key, public_key):
        self.payload = {
            "signature": signature,
            "userName": username,
            "randomKey": random_key,
            "publicKey": public_key,
            "encryptType": "MD5",
            "ipAddress": "",
            "clientType": "WINPC_V2",
            "userType": "0",
        }

    @staticmethod
    def _hash(data):
        return hashlib.md5(data.encode("utf-8")).hexdigest()

    def create_signature(self, username, password, realm, random_key):
        h = self._hash(password)
        h = self._hash(username + h)
        h = self._hash(h)
        h = self._hash(f"{username}:{realm}:{h}")
        h = self._hash(f"{h}:{random_key}")
        self.signature = h

    def set_res(self, data):
        try:
            self.res = json.loads(data)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"error on unmarshall auth response\n{exc}") from exc


class Defense:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def auth(self, username, password, rsa_pk):
        auth_endpoint = "/brms/api/v1.0/accounts/authorize"

        enc_data = EncData()
        auth = Auth()

        defense_api = API(self.host, self.port)

        enc_data.create_payload(username)
        _, enc_data_res = defense_api.post(auth_endpoint, enc_data.payload)
        enc_data.set_res(enc_data_res)

        if rsa_pk:
            enc_data.res["publickey"] = rsa_pk

        auth.create_signature(
            username,
            password,
            enc_data.res.get("realm", ""),
            enc_data.res.get("randomKey", ""),
        )
        auth.create_payload(
            auth.signature,
            username,
            enc_data.res.get("randomKey", ""),
            enc_data.res.get("publickey", ""),
        )

        _, auth_res = defense_api.post(auth_endpoint, auth.payload)
        auth.set_res(auth_res)

        if not auth.res.get("token"):
            raise RuntimeError("token not created")

        return auth.res


def to_clean_public_key(pub_key):
    public_key_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    clean_lines = []
    for line in public_key_pem.splitlines():
        if "PUBLIC KEY" in line or not line.strip():
            continue
        clean_lines.append(line.strip())
    return "".join(clean_lines)


def get_defense_keys_and_token(cfg):
    rsa_x = RSAx()
    rsa_x.generate_key_pair(2048)

    pub_clean = to_clean_public_key(rsa_x.get_public_key())
    defense = Defense(cfg.defense_host, str(cfg.defense_https_port))
    res = defense.auth(cfg.defense_username, cfg.defense_password, pub_clean)

    secret_vector = rsa_x.decrypt(res.get("secretVector", ""))
    secret_key = rsa_x.decrypt(res.get("secretKey", ""))

    return (
        secret_key.decode("utf-8", errors="replace"),
        secret_vector.decode("utf-8", errors="replace"),
        res.get("token", ""),
    )


def get_mq_config(cfg, token):
    mq_endpoint = "/brms/api/v1.0/BRM/Config/GetMqConfig"
    defense_api = API(cfg.defense_host, str(cfg.defense_https_port), token=token)

    _, res = defense_api.post(mq_endpoint, {})
    try:
        out = json.loads(res)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"error unmarshalling GetMqConfig response: {exc}") from exc

    if out.get("code") != 1000:
        raise RuntimeError(f"GetMqConfig returned code={out.get('code')} desc={out.get('desc')}")

    data = out.get("data", {})
    if not data.get("password") or not data.get("userName") or not data.get("mqtt"):
        raise RuntimeError("GetMqConfig returned missing fields (password/userName/mqtt)")

    return out


def pkcs5_unpadding(src):
    length = len(src)
    if length == 0:
        return src
    unpadding = src[-1]
    if unpadding <= 0 or unpadding > AES_BLOCK_SIZE or unpadding > length:
        return src
    return src[: length - unpadding]


def get_aes_decrypted(encrypted_base64, key, iv):
    ciphertext = base64.b64decode(encrypted_base64)
    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("ciphertext is not a multiple of block size")

    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = pkcs5_unpadding(plaintext)
    return plaintext.decode("utf-8", errors="replace")


def decrypt_password(password_hex, secret_key, secret_vector):
    password_bytes = bytes.fromhex(password_hex)
    password_base64 = base64.b64encode(password_bytes).decode("ascii")
    return get_aes_decrypted(password_base64, secret_key, secret_vector)


def message_handler(_client, _userdata, msg):
    global current_def_payload
    current_def_payload = msg.payload.decode("utf-8", errors="replace")
    print(f"Tamanho: {len(current_def_payload)}")
    print(f"Tamanho event: {len(msg.payload)}")
    print(f"Current payload: {current_def_payload}")
    print(f"Topic: {msg.topic}")

    try:
        json.loads(msg.payload)
    except json.JSONDecodeError as exc:
        print(f"Error decoding JSON: {exc}")


def subscribe_defense(client, def_topic):
    global current_def_topic
    print(f"Subscribing to topic: {def_topic}")
    result, _mid = client.subscribe(def_topic, qos=0)
    if result != mqtt.MQTT_ERR_SUCCESS:
        raise SystemExit(f"Error subscribing to topic: {mqtt.error_string(result)}")
    print(f"Subscribed to topic: {def_topic}")
    current_def_topic = def_topic


def fallback_string(flag_value, env_var, default):
    if flag_value:
        return flag_value
    return os.getenv(env_var, default)


def fallback_int(flag_value, env_var, default):
    if flag_value not in (None, 0):
        return flag_value
    raw = os.getenv(env_var)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=None, help="Defense host")
    parser.add_argument("--port", type=int, default=None, help="Defense HTTPS port")
    parser.add_argument("--user", default=None, help="Defense username")
    parser.add_argument("--pass", dest="password", default=None, help="Defense password")
    parser.add_argument(
        "--topic",
        default="mq/event/msg/topic/#",
        help="MQTT topic to subscribe",
    )
    parser.add_argument("--clientid", default="mqtt-client-idDADAsa", help="MQTT client id")
    args = parser.parse_args()

    cfg = Config(
        defense_host=fallback_string(args.host, "DEFENSE_HOST", DEFAULT_DEFENSE_HOST),
        defense_https_port=fallback_int(args.port, "DEFENSE_PORT", DEFAULT_DEFENSE_PORT),
        defense_username=fallback_string(args.user, "DEFENSE_USER", DEFAULT_DEFENSE_USER),
        defense_password=fallback_string(
            args.password,
            "DEFENSE_PASSWORD",
            DEFAULT_DEFENSE_PASSWORD,
        ),
    )
    if (
        not cfg.defense_host
        or not cfg.defense_https_port
        or not cfg.defense_username
        or not cfg.defense_password
    ):
        raise SystemExit(
            "missing required params: --host --port --user --pass "
            "(or DEFENSE_HOST/DEFENSE_PORT/DEFENSE_USER/DEFENSE_PASSWORD)"
        )

    secret_key, secret_vector, token = get_defense_keys_and_token(cfg)
    if not token:
        raise SystemExit("token not created")

    mq_cfg = get_mq_config(cfg, token)
    mqtt_pass = decrypt_password(mq_cfg["data"]["password"], secret_key, secret_vector)

    mqtt_value = mq_cfg["data"]["mqtt"]
    parts = mqtt_value.split(":")
    if len(parts) != 2:
        raise SystemExit(f"invalid mqCfg.data.mqtt value: {mqtt_value}")

    mqtt_host = parts[0]
    mqtt_port = int(parts[1])
    use_tls = mq_cfg["data"].get("enableTls") == "1"
    broker_url = ("ssl" if use_tls else "tcp") + f"://{mqtt_host}:{mqtt_port}"

    client = mqtt.Client(client_id=args.clientid, protocol=mqtt.MQTTv311)
    client.username_pw_set(mq_cfg["data"]["userName"], mqtt_pass)
    if use_tls:
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)
    client.on_message = message_handler

    rc = client.connect(mqtt_host, mqtt_port, keepalive=60)
    if rc != mqtt.MQTT_ERR_SUCCESS:
        raise SystemExit(f"Error connecting to MQTT broker: {mqtt.error_string(rc)}")

    print(f"Connected MQTT: {broker_url} (tls={use_tls}) user={mq_cfg['data']['userName']}")
    subscribe_defense(client, args.topic)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("\nDisconnecting...")
        client.disconnect()


if __name__ == "__main__":
    main()
