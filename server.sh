#!/bin/bash

./camostream -role=server -mode=tcp -listen=:39001 -forward=127.0.0.1:4141 \
  -bitrate-mbps=20 -decoy-rps=10 \
  -pcap=tcp_server.pcap -pcap-max-mb=50 -metrics=:9100 -log=info

