package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type DNSHeader struct {
	// Total 12 bytes (96 bits)
	ID      uint16 // Packet Identifier (16 bit)
	QR      bool   // Query/Response Indicator (1 bit)
	OPCODE  uint8  // Query/Response Indicator (4 bit)
	AA      bool   // Authoritative Answer (1 bit)
	TC      bool   // Truncation (1 bit)
	RD      bool   // Recursion Desired (1 bit)
	RA      bool   //  Recursion Available (1 bit)
	Z       uint8   // Reserved (3 bit)
	RCODE   uint8  // Response Code (4 bit)
	QDCOUNT uint16 // Question Count (16 bit)
	ANCOUNT uint16 // Answer Record Count (16 bit)
	NSCOUNT uint16 // Authority Record Count (16 bit)
	ARCOUNT uint16 // Additional Record Count (16 bit)
}

func (dh *DNSHeader) Serialize() []byte {
	headerSize := 12
	header := make([]byte, headerSize)

	binary.BigEndian.PutUint16(header[:2], dh.ID)
	
	if dh.QR {
		header[2] |= 0x1 << 7
	}

	opcode := dh.OPCODE & 0b1111
	header[2] |= opcode << 3

	if dh.AA {
		header[2] |= 0x1 << 2
	}

	if dh.TC {
		header[2] |= 0x1 << 1
	}

	if dh.RD {
		header[2] |= 0x1
	}

	if dh.RA {
		header[3] |= 0x1 << 7
	}

	z := dh.Z & 0b111
	header[3] |= z << 4


	rcode := dh.RCODE & 0b1111
	header[3] |= rcode

	binary.BigEndian.PutUint16(header[4:6], dh.QDCOUNT)
	binary.BigEndian.PutUint16(header[6:8], dh.ANCOUNT)
	binary.BigEndian.PutUint16(header[8:10], dh.NSCOUNT)
	binary.BigEndian.PutUint16(header[10:12], dh.ARCOUNT)
	return header
}

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

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		header := &DNSHeader{
			ID:      1234,
			QR:      true,
			OPCODE:  0,
			AA:      false,
			TC:      false,
			RD:      false,
			RA:      false,
			Z:       0,
			RCODE:   0,
			QDCOUNT: 0,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		response := header.Serialize()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
