#!/bin/bash
set -e

REMOTE="root@8.219.204.112"
PASS="kevin715041@"

run_server() {
    proto=$1
    port=$2
    echo "Starting server for $proto on port $port..."
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $REMOTE "nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto $proto -listen 0.0.0.0:$port > /dev/null 2>&1 &"
    sleep 2
}

run_client() {
    proto=$1
    port=$2
    outfile=$3
    echo "Running client for $proto..."
    ./iotbci-netbench -mode client -proto $proto -server 8.219.204.112:$port -messages 20 -size 128 -out cross_region_results/$outfile
}

mkdir -p cross_region_results

# Sudoku Pure
run_server "iotbci-sudoku-pure-tcp" 19001
run_client "iotbci-sudoku-pure-tcp" 19001 "sudoku_pure.json"

# Sudoku Packed
run_server "iotbci-sudoku-packed-tcp" 19002
run_client "iotbci-sudoku-packed-tcp" 19002 "sudoku_packed.json"

# Pure AEAD
run_server "pure-aead-tcp" 19003
run_client "pure-aead-tcp" 19003 "pure_aead.json"

# MQTT
# Note: netbench MQTT server implementation is minimal. Let's try it.
run_server "mqtt-3.1.1-qos0-tls" 19004
run_client "mqtt-3.1.1-qos0-tls" 19004 "mqtt.json"

# DTLS
# DTLS over UDP might be tricky with NAT/Firewall, but let's try.
# The thesis mentions "UoT" (UDP over TCP relay) for DTLS/CoAP. netbench might support it or use raw UDP.
# netbench uses "dtls-psk-aes128gcm" which seems to be over UDP in `proto_dtls.go`.
# The remote host 8.219.204.112 might block UDP.
run_server "dtls-psk-aes128gcm" 19005
run_client "dtls-psk-aes128gcm" 19005 "dtls.json" || echo "DTLS failed (expected if UDP blocked)"

# CoAP
run_server "coap-udp" 19006
run_client "coap-udp" 19006 "coap.json" || echo "CoAP failed (expected if UDP blocked)"

echo "Done."
