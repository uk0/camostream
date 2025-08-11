package main

import (
	"fmt"
	"net"
)

func main() {
	addr := net.UDPAddr{
		Port: 18081,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("UDP server listening on", addr.String())

	buf := make([]byte, 2048)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("read error:", err)
			continue
		}

		fmt.Printf("Received from %s: %s\n", clientAddr.String(), string(buf[:n]))

		htmlResponse := `HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 60

<html><body><h1>Hello from UDP HTML Server!</h1></body></html>`

		_, err = conn.WriteToUDP([]byte(htmlResponse), clientAddr)
		if err != nil {
			fmt.Println("write error:", err)
		}
	}
}
