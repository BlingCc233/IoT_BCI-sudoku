#!/bin/bash
set -e

mkdir -p cross_region_results

run_client() {
    proto=$1
    port=$2
    outfile=$3
    host=$4
    echo "Running client for $proto on $host:$port..."
    ./iotbci-netbench -mode client -proto $proto -server $host:$port -messages 20 -size 128 -out cross_region_results/$outfile
}

# Sudoku Pure (Tunnel)
run_client "iotbci-sudoku-pure-tcp" 19001 "sudoku_pure.json" "127.0.0.1"

# Sudoku Packed (Tunnel)
run_client "iotbci-sudoku-packed-tcp" 19002 "sudoku_packed.json" "127.0.0.1"

# Pure AEAD (Tunnel)
run_client "pure-aead-tcp" 19003 "pure_aead.json" "127.0.0.1"

# MQTT (Tunnel)
run_client "mqtt-3.1.1-qos0-tls" 19004 "mqtt.json" "127.0.0.1"

# DTLS (UDP Direct)
run_client "dtls-psk-aes128gcm" 19005 "dtls.json" "8.219.204.112" || echo "DTLS client failed"

# CoAP (UDP Direct)
run_client "coap-udp" 19006 "coap.json" "8.219.204.112" || echo "CoAP client failed"

echo "Client run complete."
