import subprocess
import json
import hashlib
import secrets
import sys
import os
import random
import time
import argparse
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

# Cryptographic Constants
q = SECP256k1.order
G = SECP256k1.generator
p = SECP256k1.curve.p()

# Dummy Network Private/Public Key substitute for DKG output
secret_s = 2 
P_net = secret_s * G

# Fabric CLI Environment Variables
TEST_NET_PATH = "/home/montassar/fabric-samples/test-network"
FABRIC_CFG_PATH = "/home/montassar/fabric-samples/config"
TLS_CERT = f"{TEST_NET_PATH}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
PEER1_TLS = f"{TEST_NET_PATH}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
PEER2_TLS = f"{TEST_NET_PATH}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
ADMIN_MSP = f"{TEST_NET_PATH}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"

def execute_cli_command(command_string):
    cli_env = os.environ.copy()
    cli_env["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
    cli_env["CORE_PEER_TLS_ENABLED"] = "true"
    cli_env["CORE_PEER_LOCALMSPID"] = "Org1MSP"
    cli_env["CORE_PEER_TLS_ROOTCERT_FILE"] = PEER1_TLS
    cli_env["CORE_PEER_MSPCONFIGPATH"] = ADMIN_MSP
    cli_env["CORE_PEER_ADDRESS"] = "localhost:7051"

    result = subprocess.run(command_string, shell=True, capture_output=True, text=True, env=cli_env)
    if result.returncode != 0:
        print(f"CLI Execution Error:\n{result.stderr}")
        sys.exit(1)
    return result.stdout

def fetch_anonymity_set():
    print("1. Fetching Registry State from Ledger...")
    query_cmd = (
        f"peer chaincode query -C clindslrs -n clindslrscc "
        f"-c '{{\"function\":\"IdentityContract:GetRegistry\",\"Args\":[]}}'"
    )
    output = execute_cli_command(query_cmd)
    try:
        registry = json.loads(output)
        print(f"   -> Retrieved {len(registry)} public keys.")
        return registry
    except json.JSONDecodeError:
        print("Error parsing registry output.")
        sys.exit(1)

def hash_to_curve(data_string):
    counter = 0
    while True:
        h = hashlib.sha256(f"{data_string}{counter}".encode('utf-8')).hexdigest()
        x = int(h, 16) % p
        try:
            y_squared = (pow(x, 3, p) + 7) % p
            y = pow(y_squared, (p + 1) // 4, p)
            if pow(y, 2, p) == y_squared:
                return Point(SECP256k1.curve, x, y)
        except Exception:
            pass
        counter += 1

def hash_oracle(sid, c1, c2, L, R, A, B):
    h = hashlib.sha256()
    h.update(str(sid).encode('utf-8'))
    h.update(str(c1.x()).encode('utf-8'))
    h.update(str(c2.x()).encode('utf-8'))
    h.update(str(L.x()).encode('utf-8'))
    h.update(str(R.x()).encode('utf-8'))
    h.update(str(A.x()).encode('utf-8'))
    h.update(str(B.x()).encode('utf-8'))
    return int(h.hexdigest(), 16) % q

def generate_dslrs_signature(registry, signer_priv_key_hex, scope_m, target_n):
    start_time = time.perf_counter()
    
    actual_ring_size = target_n if target_n is not None else len(registry)
    actual_ring_size = min(max(actual_ring_size, 3), len(registry)) 
    
    print(f"2. Generating DSLRS Cryptographic Signature (n={actual_ring_size})...")
    
    d = int(signer_priv_key_hex, 16)
    P_signer = d * G
    
    signer_entry = None
    other_entries = []
    
    for pk in registry:
        x = int(pk['x'], 16)
        y = int(pk['y'], 16)
        if x == P_signer.x() and y == P_signer.y():
            signer_entry = pk
        else:
            other_entries.append(pk)
            
    if signer_entry is None:
        print("Error: Signer public key is not present in the fetched registry.")
        sys.exit(1)

    sample_size = actual_ring_size - 1
    sampled_subset = random.sample(other_entries, sample_size)
    sampled_subset.append(signer_entry)
    random.shuffle(sampled_subset)
    
    pi = -1
    ring_points = []
    for idx, pk in enumerate(sampled_subset):
        x = int(pk['x'], 16)
        y = int(pk['y'], 16)
        ring_points.append(Point(SECP256k1.curve, x, y))
        if x == P_signer.x() and y == P_signer.y():
            pi = idx

    n = len(ring_points)
    
    Hp_s = hash_to_curve(f"{P_signer.x()}{scope_m}")
    I_scope = d * Hp_s
    
    r = secrets.randbelow(q - 1) + 1
    r_dean = secrets.randbelow(q - 1) + 1
    r_z = secrets.randbelow(q - 1) + 1
    
    C1 = r_dean * G
    C2 = P_signer + (r_dean * P_net)
    
    L_s = r * G
    R_s = r * Hp_s
    A_s = r_z * G
    B_s = r_z * P_net
    
    ch = [0] * n
    x = [0] * n
    z = [0] * n
    
    next_idx = (pi + 1) % n
    ch[next_idx] = hash_oracle(scope_m, C1, C2, L_s, R_s, A_s, B_s)
    
    for j in range(1, n):
        i = (pi + j) % n
        x[i] = secrets.randbelow(q - 1) + 1
        z[i] = secrets.randbelow(q - 1) + 1
        
        Hp_i = hash_to_curve(f"{ring_points[i].x()}{scope_m}")
        
        L_i = (x[i] * G) + (ch[i] * ring_points[i])
        R_i = (x[i] * Hp_i) + (ch[i] * I_scope)
        
        neg_ch_i = (q - ch[i]) % q
        A_i = (z[i] * G) + (C1 * neg_ch_i)
        
        neg_Pi = ring_points[i] * (q - 1)
        C2_minus_Pi = C2 + neg_Pi
        B_i = (z[i] * P_net) + (C2_minus_Pi * neg_ch_i)
        
        next_idx = (i + 1) % n
        ch[next_idx] = hash_oracle(scope_m, C1, C2, L_i, R_i, A_i, B_i)
        
    x[pi] = (r - ch[pi] * d) % q
    z[pi] = (r_z + ch[pi] * r_dean) % q
    
    signature_payload = {
        "I_scope": {
            "x": hex(I_scope.x())[2:],
            "y": hex(I_scope.y())[2:]
        },
        "L": sampled_subset,
        "SID": scope_m,
        "P_net": {
            "x": hex(P_net.x())[2:],
            "y": hex(P_net.y())[2:]
        },
        "C_1": {
            "x": hex(C1.x())[2:],
            "y": hex(C1.y())[2:]
        },
        "C_2": {
            "x": hex(C2.x())[2:],
            "y": hex(C2.y())[2:]
        },
        "ch_0": hex(ch[0])[2:],
        "x": [hex(val)[2:] for val in x],
        "z": [hex(val)[2:] for val in z]
    }
    
    end_time = time.perf_counter()
    execution_time_ms = (end_time - start_time) * 1000
    print("   -> Signature generated successfully.")
    print(f"   -> [METRICS] Client Processing Time: {execution_time_ms:.2f} ms")
    
    return signature_payload

def submit_transaction(action, scope_old, scope_new, signature_payload):
    print(f"3. Submitting {action.upper()} Transaction to Ledger...")
    
    sig_json_str = json.dumps(signature_payload, separators=(',', ':'))
    esc_sig = sig_json_str.replace('"', '\\"')
    esc_scope_old = scope_old.replace('"', '\\"')
    
    if action == "publish":
        fcn = "PublishConsent"
        args_str = f'"{esc_scope_old}", "{esc_sig}"'
    elif action == "revoke":
        fcn = "RevokeOrUpdateConsent"
        args_str = f'"{esc_scope_old}", "REV", "{esc_sig}"'
    elif action == "update":
        fcn = "RevokeOrUpdateConsent"
        esc_scope_new = scope_new.replace('"', '\\"')
        args_str = f'"{esc_scope_old}", "{esc_scope_new}", "{esc_sig}"'

    invoke_cmd = (
        f"peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls "
        f"--cafile {TLS_CERT} -C clindslrs -n clindslrscc "
        f"--peerAddresses localhost:7051 --tlsRootCertFiles {PEER1_TLS} "
        f"--peerAddresses localhost:9051 --tlsRootCertFiles {PEER2_TLS} "
        f"-c '{{\"function\":\"ConsentManagementContract:{fcn}\",\"Args\":[{args_str}]}}'"
    )
    
    start_time = time.perf_counter()
    output = execute_cli_command(invoke_cmd)
    end_time = time.perf_counter()
    
    execution_time_ms = (end_time - start_time) * 1000
    
    print("   -> Invocation Complete. Output:")
    print(output)
    print(f"   -> [METRICS] Total End-to-End Consensus Time: {execution_time_ms:.2f} ms")

def simulate_deanonymization(target_scope):
    print(f"3. Simulating Committee Deanonymization for scope: {target_scope}")
    
    # 3.1 Fetch C1 from target record
    query_cmd = (
        f"peer chaincode query -C clindslrs -n clindslrscc "
        f"-c '{{\"function\":\"ConsentManagementContract:QueryConsent\",\"Args\":[\"{target_scope}\"]}}'"
    )
    output = execute_cli_command(query_cmd)
    try:
        record = json.loads(output)
        c1_data = record['sigma']['C_1']
        C1 = Point(SECP256k1.curve, int(c1_data['x'], 16), int(c1_data['y'], 16))
    except (json.JSONDecodeError, KeyError):
        print("Error: Could not retrieve valid C_1 point from the specified consent record.")
        sys.exit(1)

    # 3.2 Generate random polynomial and shares locally
    start_gen_time = time.perf_counter()
    k = 8
    coeffs = [secret_s] + [secrets.randbelow(q) for _ in range(k-1)]
    
    shares = []
    for j in range(1, k + 1):
        omega = j
        s_j = 0
        for power, c in enumerate(coeffs):
            s_j = (s_j + c * pow(omega, power, q)) % q
        D_j = s_j * C1
        shares.append((omega, D_j))
        
    end_gen_time = time.perf_counter()
    gen_time_ms = (end_gen_time - start_gen_time) * 1000
    print(f"   -> [METRICS] Local Polynomial & Share Generation Time: {gen_time_ms:.2f} ms")

    # 3.3 Submit 8 shares sequentially
    total_consensus_time_ms = 0
    
    for omega, D_j in shares:
        share_payload = {
            "omega": hex(omega)[2:],
            "D": {
                "x": hex(D_j.x())[2:],
                "y": hex(D_j.y())[2:]
            }
        }
        
        sig_json_str = json.dumps(share_payload, separators=(',', ':'))
        esc_sig = sig_json_str.replace('"', '\\"')
        
        invoke_cmd = (
            f"peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls "
            f"--cafile {TLS_CERT} -C clindslrs -n clindslrscc "
            f"--peerAddresses localhost:7051 --tlsRootCertFiles {PEER1_TLS} "
            f"--peerAddresses localhost:9051 --tlsRootCertFiles {PEER2_TLS} "
            f"-c '{{\"function\":\"ConsentManagementContract:SubmitDeanonymizationShare\",\"Args\":[\"{target_scope}\", \"{esc_sig}\"]}}'"
        )
        
        print(f"   -> Submitting Share (omega={omega})...")
        start_invoke = time.perf_counter()
        execute_cli_command(invoke_cmd)
        end_invoke = time.perf_counter()
        
        total_consensus_time_ms += (end_invoke - start_invoke) * 1000
        time.sleep(2.5) # Fabric block-cut delay buffer
        
    avg_consensus_time = total_consensus_time_ms / k
    print(f"   -> [METRICS] Average End-to-End Consensus Time (per share): {avg_consensus_time:.2f} ms")
    print(f"   -> [METRICS] Cumulative Consensus Time (8 shares): {total_consensus_time_ms:.2f} ms")
        
    print("   -> Threshold reached. Querying Final Identity...")
    final_output = execute_cli_command(query_cmd)
    final_record = json.loads(final_output)
    
    print("\n[DEANONYMIZATION RESULT]")
    print(f"Status: {final_record['status']}")
    print(f"Signer Public Key: \n{json.dumps(final_record['signer'], indent=2)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DSLRS Fabric Client")
    parser.add_argument("action", choices=["publish", "revoke", "update", "deanonymize"], help="Action to execute")
    parser.add_argument("priv_key_hex", help="Signer's private key (or dummy string for deanonymize)")
    parser.add_argument("scope_old", help="Target consent scope hash")
    parser.add_argument("--scope_new", help="New consent scope hash (Required only for 'update')", default="REV")
    parser.add_argument("-n", "--ring_size", type=int, default=None, help="Desired anonymity ring size (defaults to full registry)")
    
    args = parser.parse_args()
    
    if args.action == "deanonymize":
        simulate_deanonymization(args.scope_old)
        sys.exit(0)
        
    if args.action == "update" and args.scope_new == "REV":
        print("Error: --scope_new argument is required when executing 'update'.")
        sys.exit(1)
        
    registry_data = fetch_anonymity_set()
    signature_data = generate_dslrs_signature(registry_data, args.priv_key_hex, args.scope_old, args.ring_size)
    submit_transaction(args.action, args.scope_old, args.scope_new, signature_data)