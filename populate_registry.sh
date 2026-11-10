#!/bin/bash

NUM_KEYS=1
TEST_NET_PATH="/home/montassar/fabric-samples/test-network"
CHAINCODE_PATH="/home/montassar/fabric-samples/chaincode/dslrs"

while getopts "n:" flag; do
    case "${flag}" in
        n) NUM_KEYS=${OPTARG};;
        *) echo "Usage: $0 -n <number_of_keys>"; exit 1;;
    esac
done

for ((i=1; i<=NUM_KEYS; i++)); do
    echo "Generating and submitting identity payload $i of $NUM_KEYS..."
    
    # 1. Execute python and capture output
    PY_OUTPUT=$(python3 ${CHAINCODE_PATH}/generate_registry_payload.py)
    
    # 2. Extract raw JSON safely (omitting line start anchors for encoding resilience)
    RAW_ARG_1=$(echo "$PY_OUTPUT" | grep "export ARG_1=" | cut -d"'" -f2)
    
    # 3. Diagnostic check: abort if extraction yields empty strings
    if [ -z "$RAW_ARG_1" ]; then
        echo "CRITICAL ERROR: Payload extraction failed. Python output was:"
        echo "$PY_OUTPUT"
        exit 1
    fi
    
    # 4. Escape double quotes natively in Bash
    ESC_ARG_1=$(echo "$RAW_ARG_1" | sed 's/"/\\"/g')
    
    # 5. Execute peer invocation
    peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${TEST_NET_PATH}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C clindslrs -n clindslrscc --peerAddresses localhost:7051 --tlsRootCertFiles ${TEST_NET_PATH}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${TEST_NET_PATH}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"IdentityContract:RegisterPublicKey","Args":["'"$ESC_ARG_1"'"]}'
    
    echo "Waiting for block commit..."
    sleep 3
done

echo "Registry population execution complete."
