#!/bin/bash

./camostream -role=client -mode=udp -listen=:37001 -server=127.0.0.1:39001 \
  -wire=rtpish -fps=60 -bitrate-mbps=20 \
  -decoy-rps=12 \
  -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
  -pcap=udp_client.pcap -pcap-max-mb=100 -metrics=:9101 -log=info