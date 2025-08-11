#!/bin/bash

./camostream -role=client -mode=tcp -listen=:37001 -server=127.0.0.1:39001 \
  -bitrate-mbps=20 -decoy-rps=10 \
  -pcap=tcp_client.pcap -pcap-max-mb=50 -metrics=:9101 -log=info