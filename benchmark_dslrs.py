import time
import csv
import secrets
import sys
import json
import argparse
import contextlib
import io
import os
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

# Import core logic from the existing client implementation
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import dslrs_client

def generate_scope():
    return secrets.token_hex(8)[:15]

def submit_invoke(fcn, args_list):
    args_str = ", ".join([f'"{str(a).replace("\"", "\\\"")}"' for a in args_list])
    invoke_cmd = (
        f"peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls "
        f"--cafile {dslrs_client.TLS_CERT} -C clindslrs -n clindslrscc "
        f"--peerAddresses localhost:7051 --tlsRootCertFiles {dslrs_client.PEER1_TLS} "
        f"--peerAddresses localhost:9051 --tlsRootCertFiles {dslrs_client.PEER2_TLS} "
        f"-c '{{\"function\":\"ConsentManagementContract:{fcn}\",\"Args\":[{args_str}]}}'"
    )
    start_time = time.perf_counter()
    dslrs_client.execute_cli_command(invoke_cmd)
    end_time = time.perf_counter()
    return (end_time - start_time) * 1000

def silent_generate_signature(registry, priv_key_hex, scope, n):
    with contextlib.redirect_stdout(io.StringIO()):
        start_time = time.perf_counter()
        sig = dslrs_client.generate_dslrs_signature(registry, priv_key_hex, scope, n)
        gen_time = (time.perf_counter() - start_time) * 1000
    return sig, gen_time

def benchmark_deanonymization(target_scope):
    query_cmd = (
        f"peer chaincode query -C clindslrs -n clindslrscc "
        f"-c '{{\"function\":\"ConsentManagementContract:QueryConsent\",\"Args\":[\"{target_scope}\"]}}'"
    )
    output = dslrs_client.execute_cli_command(query_cmd)
    record = json.loads(output)
    c1_data = record['sigma']['C_1']
    C1 = Point(SECP256k1.curve, int(c1_data['x'], 16), int(c1_data['y'], 16))

    start_gen = time.perf_counter()
    k = 8
    coeffs = [dslrs_client.secret_s] + [secrets.randbelow(dslrs_client.q) for _ in range(k-1)]
    shares = []
    
    for j in range(1, k + 1):
        omega = j
        s_j = 0
        for power, c in enumerate(coeffs):
            s_j = (s_j + c * pow(omega, power, dslrs_client.q)) % dslrs_client.q
        D_j = s_j * C1
        shares.append((omega, D_j))
        
    gen_time_ms = (time.perf_counter() - start_gen) * 1000

    total_submit_ms = 0
    for omega, D_j in shares:
        share_payload = {
            "omega": hex(omega)[2:],
            "D": {
                "x": hex(D_j.x())[2:],
                "y": hex(D_j.y())[2:]
            }
        }
        sig_json_str = json.dumps(share_payload, separators=(',', ':'))
        
        with contextlib.redirect_stdout(io.StringIO()):
            submit_time = submit_invoke("SubmitDeanonymizationShare", [target_scope, sig_json_str])
            
        total_submit_ms += submit_time
        time.sleep(2.5) 

    return gen_time_ms, total_submit_ms

def run_benchmark(priv_key_hex):
    print("Fetching Registry State...")
    registry = dslrs_client.fetch_anonymity_set()
    
    iterations = 100
    ring_sizes = [8, 16, 32]
    csv_filename = "dslrs_performance_benchmark.csv"

    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Ring_Size", "Iteration", "Phase", "Client_Gen_Time_ms", "E2E_Consensus_Time_ms"])

        for n in ring_sizes:
            print(f"\n=== Starting Benchmark Suite for Ring Size: {n} ===")
            for i in range(1, iterations + 1):
                sys.stdout.write(f"\rProcessing Iteration {i}/{iterations} [n={n}]")
                sys.stdout.flush()

                scope_1 = generate_scope()
                scope_2 = generate_scope()

                # Phase 1: Publish (SID = scope_1)
                sig_pub, gen_pub = silent_generate_signature(registry, priv_key_hex, scope_1, n)
                sig_json_pub = json.dumps(sig_pub, separators=(',', ':'))
                e2e_pub = submit_invoke("PublishConsent", [scope_1, sig_json_pub])
                writer.writerow([n, i, "Publish", round(gen_pub, 2), round(e2e_pub, 2)])
                time.sleep(2.5)

                # Phase 2: Update (SID = scope_1, Targets = scope_1 -> scope_2)
                sig_upd, gen_upd = silent_generate_signature(registry, priv_key_hex, scope_1, n)
                sig_json_upd = json.dumps(sig_upd, separators=(',', ':'))
                e2e_upd = submit_invoke("RevokeOrUpdateConsent", [scope_1, scope_2, sig_json_upd])
                writer.writerow([n, i, "Update", round(gen_upd, 2), round(e2e_upd, 2)])
                time.sleep(2.5)

                # Phase 3: Revoke (SID = scope_1, Target = scope_2)
                sig_rev, gen_rev = silent_generate_signature(registry, priv_key_hex, scope_1, n)
                sig_json_rev = json.dumps(sig_rev, separators=(',', ':'))
                e2e_rev = submit_invoke("RevokeOrUpdateConsent", [scope_2, "REV", sig_json_rev])
                writer.writerow([n, i, "Revoke", round(gen_rev, 2), round(e2e_rev, 2)])
                time.sleep(2.5)

                # Phase 4: Deanonymize (Targets record at scope_2)
                gen_dean, e2e_dean = benchmark_deanonymization(scope_2)
                writer.writerow([n, i, "Deanonymize", round(gen_dean, 2), round(e2e_dean, 2)])

    print(f"\n[INFO] Benchmark complete. Results written to {csv_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DSLRS Performance Benchmark")
    parser.add_argument("priv_key_hex", help="Signer's private key in hex format")
    args = parser.parse_args()
    
    run_benchmark(args.priv_key_hex)