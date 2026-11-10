import json
import secrets
from ecdsa import SECP256k1

q = SECP256k1.order
G = SECP256k1.generator

def generate_payload():
    d = secrets.randbelow(q - 1) + 1
    P = d * G

    P_hex = {
        "x": hex(P.x())[2:],
        "y": hex(P.y())[2:]
    }

    # Persist the private key locally
    with open("/home/montassar/fabric-samples/chaincode/dslrs/signer_keys.txt", "a") as key_file:
        key_file.write(f"PrivateKey: {hex(d)[2:]} | PublicKey_X: {hex(P.x())[2:]}\n")

    print(f"export ARG_1='{json.dumps(P_hex, separators=(',', ':'))}'")

if __name__ == "__main__":
    generate_payload()
