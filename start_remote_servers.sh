#!/bin/bash
pkill -f iotbci-netbench
chmod +x /root/iotbci-sudoku/iotbci-netbench

# Start servers for all protocols
nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto iotbci-sudoku-pure-tcp -listen 0.0.0.0:19001 > /root/iotbci-sudoku/server_pure.log 2>&1 &
nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto iotbci-sudoku-packed-tcp -listen 0.0.0.0:19002 > /root/iotbci-sudoku/server_packed.log 2>&1 &
nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto pure-aead-tcp -listen 0.0.0.0:19003 > /root/iotbci-sudoku/server_aead.log 2>&1 &
nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto mqtt-3.1.1-qos0-tls -listen 0.0.0.0:19004 > /root/iotbci-sudoku/server_mqtt.log 2>&1 &
nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto dtls-psk-aes128gcm -listen 0.0.0.0:19005 > /root/iotbci-sudoku/server_dtls.log 2>&1 &
nohup /root/iotbci-sudoku/iotbci-netbench -mode server -proto coap-udp -listen 0.0.0.0:19006 > /root/iotbci-sudoku/server_coap.log 2>&1 &

echo "Servers started."
ps aux | grep iotbci-netbench
