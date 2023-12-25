package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	TypeA     = uint16(1)  // a host address
	TypeNS    = uint16(2)  // an authoritative name server
	TypeMD    = uint16(3)  // a mail destination (Obsolete - use MX)
	TypeMF    = uint16(4)  // a mail forwarder (Obsolete - use MX)
	TypeCNAME = uint16(5)  // the canonical name for an alias
	TypeSOA   = uint16(6)  // marks the start of a zone of authority
	TypeMB    = uint16(7)  // a mailbox domain name (EXPERIMENTAL)
	TypeMG    = uint16(8)  // a mail group member (EXPERIMENTAL)
	TypeMR    = uint16(9)  // a mail rename domain name (EXPERIMENTAL)
	TypeNULL  = uint16(10) //	a null RR (EXPERIMENTAL)
	TypeWKS   = uint16(11) //	a well known service description
	TypePTR   = uint16(12) //	a domain name pointer
	TypeHINFO = uint16(13) //	host information
	TypeMINFO = uint16(14) //	mailbox or mail list information
	TypeMX    = uint16(15) //	mail exchange
	TypeTXT   = uint16(16) //	text strings
	ClassIN   = uint16(1)  // the Internet
	ClassCS   = uint16(2)  // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	ClassCH   = uint16(3)  // the CHAOS class
	ClassHS   = uint16(4)  // Hesiod [Dyer 87
)

type DNSResponse struct {
	Header    *DNSHeader
	Questions []*Question
}

func newDNSResponse() *DNSResponse {
	h := &DNSHeader{}
	qs := []*Question{}

	return &DNSResponse{Header: h, Questions: qs}
}

func (dr *DNSResponse) SetId(id uint16) {
	dr.Header.Id = id
}

func (dr *DNSResponse) AsQuery() {
	dr.Header.Qr = true
}

func (dr *DNSResponse) AddQuestion(domain string, qType, qClass uint16) {
	q := newQuestion(domain, qType, qClass)
	dr.Questions = append(dr.Questions, q)
	dr.Header.QDCount++
}

func (dr *DNSResponse) Serialize() []byte {
	s := []byte{}
  s = append(s, dr.Header.Serialize()...)
	for _, q := range dr.Questions {
		s = append(s, q.Serialize()...)
	}

	return s
}

type DNSHeader struct {
	// Total 12 bytes (96 bits)
	Id      uint16 // Packet Identifier (16 bit)
	Qr      bool   // Query/Response Indicator (1 bit)
	OPCode  uint8  // Operation Code (4 bit)
	AA      bool   // Authoritative Answer (1 bit)
	TC      bool   // Truncation (1 bit)
	RD      bool   // Recursion Desired (1 bit)
	RA      bool   //  Recursion Available (1 bit)
	Z       uint8  // Reserved (3 bit)
	RCode   uint8  // Response Code (4 bit)
	QDCount uint16 // Question Count (16 bit)
	ANCount uint16 // Answer Record Count (16 bit)
	NSCount uint16 // Authority Record Count (16 bit)
	ARCount uint16 // Additional Record Count (16 bit)
}

func (dh *DNSHeader) Serialize() []byte {
	headerSize := 12
	header := make([]byte, headerSize)

	binary.BigEndian.PutUint16(header[:2], dh.Id)

	if dh.Qr {
		header[2] |= 0x1 << 7
	}
	opcode := dh.OPCode & 0b1111
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

	rcode := dh.RCode & 0b1111
	header[3] |= rcode

	binary.BigEndian.PutUint16(header[4:6], dh.QDCount)
	binary.BigEndian.PutUint16(header[6:8], dh.ANCount)
	binary.BigEndian.PutUint16(header[8:10], dh.NSCount)
	binary.BigEndian.PutUint16(header[10:12], dh.ARCount)
	return header
}

type Question struct {
	Name  []byte
	Type  uint16
	Class uint16
}

func newQuestion(domain string, qType, qClass uint16) *Question {
	name := []byte{}
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		bs := []byte(part)
		name = append(name, byte(len(bs)))
		name = append(name, bs...)
	}

	name = append(name, 0)

	return &Question{Name: name, Type: uint16(qType), Class: qClass}
}

func (q *Question) Serialize() []byte {
	serialized := make([]byte, len(q.Name))
	copy(serialized, q.Name)

	binary.BigEndian.AppendUint16(serialized, q.Type)
	binary.BigEndian.AppendUint16(serialized, q.Class)

	return serialized
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

		dnsResponse := newDNSResponse()
		dnsResponse.SetId(1234)
		dnsResponse.AsQuery()
		dnsResponse.AddQuestion("codecrafters.io", TypeA, ClassIN)

		response := dnsResponse.Serialize()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
