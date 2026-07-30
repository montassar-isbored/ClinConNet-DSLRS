import hashlib
import json
import secrets
from ecdsa import SECP256k1

q = SECP256k1.order
G = SECP256k1.generator
SID_1 = "SID_1_REGISTRY"

def generate_payload():
    d = secrets.randbelow(q - 1) + 1
    P = d * G

    k = secrets.randbelow(q - 1) + 1
    R = k * G

    h1 = hashlib.sha256()
    h1.update(f"{P.x()},{P.y()}".encode('utf-8'))
    h1.update(SID_1.encode('utf-8'))
    m_i = int(h1.hexdigest(), 16) % q

    h2 = hashlib.sha256()
    h2.update(f"{P.x()}{P.y()}".encode('utf-8'))
    h2.update(f"{R.x()}{R.y()}".encode('utf-8'))
    h2.update(str(m_i).encode('utf-8'))
    e = int(h2.hexdigest(), 16) % q

    s = (k + e * d) % q

    P_hex = {
        "x": hex(P.x())[2:],
        "y": hex(P.y())[2:]
    }
    
    pi_hex = {
        "R_x": hex(R.x())[2:],
        "R_y": hex(R.y())[2:],
        "s": hex(s)[2:]
    }

    # Persist the private key locally
    with open("/home/montassar/fabric-samples/chaincode/dslrs/signer_keys.txt", "a") as key_file:
        key_file.write(f"PrivateKey: {hex(d)[2:]} | PublicKey_X: {hex(P.x())[2:]}\n")

    print(f"export ARG_1='{json.dumps(P_hex, separators=(',', ':'))}'")
    print(f"export ARG_2='{json.dumps(pi_hex, separators=(',', ':'))}'")

if __name__ == "__main__":
    generate_payload()
