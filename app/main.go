package main

import (
	"flag"
	"fmt"
	"net"
)


func main() {
	addr := ""

	resolver := flag.String("resolver", "", "resolver address")
	flag.Parse()

	if *resolver != "" {
		addr = *resolver
	}

	fmt.Printf("Resolver addresss %q\n", addr)

	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()


	resolverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
	}

	resolverConn, err := net.DialUDP("udp", nil, resolverAddr)
	if err != nil {
		fmt.Println("Failed to dial UDP address:", err)
	}
	defer resolverConn.Close()

	buf := make([]byte, 512)

	for {
		reqDns, source := waitForDns(udpConn, buf)
		respDns := forward(reqDns, resolverConn, resolverAddr)
		sendDns(respDns, udpConn, source)
	}
}

func forward(reqDns *DNS, resolverConn *net.UDPConn, addr *net.UDPAddr) *DNS {
	respDns := NewResponseDns(reqDns)
	buf := make([]byte, 512)

	for _, q := range reqDns.Questions {
		dns := NewQueryDns(reqDns)
		dns.AddQuestion(q.Name, q.Type, q.Class)

		fmt.Printf("Forwarding packet with id: %d, to %v, contains: %s\n", dns.Header.Id, addr, dns.Serialize())
		_, err := resolverConn.Write(dns.Serialize())
    if err != nil {
			fmt.Printf("Could not write to resolver conn, err: %v", err)
    }
		receivedDns, _ := waitForDns(resolverConn, buf)

		for i := 0; i < int(receivedDns.Header.QDCount); i++ {
			receivedQ := receivedDns.Questions[i]
			respDns.AddQuestion(receivedQ.Name, receivedQ.Type, receivedQ.Class)
		}

		for i := 0; i < int(receivedDns.Header.ANCount); i++ {
			receivedRr := receivedDns.ResourceRecords[i]
			respDns.AddResourceRecord(
				receivedRr.Name,
				receivedRr.Type,
				receivedRr.Class,
				receivedRr.TTL,
				receivedRr.Data,
			)
		}
	}

	return respDns
}

func sendDns(dns *DNS, udpConn *net.UDPConn, udpAddr *net.UDPAddr) {
	serialized := dns.Serialize()
	fmt.Printf("Sending to %d bytes to %v: id: %d\n", len(serialized), udpAddr, dns.Header.Id)
	_, err := udpConn.WriteToUDP(serialized, udpAddr)
	if err != nil {
		fmt.Println("Failed to send response:", err)
	}
}

func waitForDns(udpConn *net.UDPConn, buf []byte) (*DNS, *net.UDPAddr) {
	fmt.Println("Waiting for DNS")

	size, source, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		fmt.Println("Error receiving data:", err)
	}

	receivedData := string(buf[:size])
	receivedDns := ParseDNS([]byte(receivedData))
	fmt.Printf("Received %d bytes from %v id %d\n", size, source, receivedDns.Header.Id)

	return receivedDns, source
}

func literalFormat(array []byte) string {
	s := fmt.Sprint("[]byte{")
	for i, b := range array {
		s += fmt.Sprintf("0x%02X", b)
		if i < len(array)-1 {
			s += fmt.Sprint(", ")
		}
	}
	s += fmt.Sprintln("}")

	return s
}
