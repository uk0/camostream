#!/bin/bash

./camostream -role=server -mode=udp -listen=:39001 -forward=127.0.0.1:18081 \
  -wire=rtpish -fps=60 -bitrate-mbps=20 \
  -decoy-rps=12 \
  -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
  -pcap=udp_server.pcap -pcap-max-mb=100 -metrics=:9100 -log=info

