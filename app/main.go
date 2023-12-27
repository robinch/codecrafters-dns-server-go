package main

import (
	"fmt"
	"net"
)

func main() {
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

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		// fmt.Printf("recieved\n%s\n", literalFormat(buf[:size]))
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)
		// fmt.Printf("Recieved id %d\n", binary.BigEndian.Uint16(buf[:2]))

		reqDns := ParseDNS([]byte(receivedData))

		var rCode uint8
		if reqDns.Header.OPCode == 0 {
			rCode = 0
		} else {
			rCode = 4
		}

		dns := newDNS()
		dns.Header.Id = reqDns.Header.Id
		dns.Header.OPCode = reqDns.Header.OPCode
		dns.Header.RD = reqDns.Header.RD
		dns.Header.RCode = rCode
		dns.AsQuery()

		for i := 0; i < int(reqDns.Header.QDCount); i++ {
			domain := reqDns.Questions[i].Name
			dns.AddQuestion(domain, TypeA, ClassIN)
		}

		for i := 0; i < int(reqDns.Header.QDCount); i++ {
			domain := reqDns.Questions[i].Name
			dns.AddResourceRecord(domain, TypeA, ClassIN, 60, "8.8.8.8")
		}

		// fmt.Printf("ID: %d\n", dns.Header.Id)
		response := dns.Serialize()

		// fmt.Printf("Sending %d bytes from %s: %s\n", len(response), source, string(response))

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
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
