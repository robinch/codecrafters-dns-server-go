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

type DNS struct {
	Header          *DNSHeader
	Questions       []*Question
	ResourceRecords []*ResourceRecord
}

func newDNS() *DNS {
	h := &DNSHeader{}
	qs := []*Question{}

	return &DNS{Header: h, Questions: qs}
}

func ParseDNS(data []byte) *DNS {
	header := ParseDNSHeader(data[0:12])
	questions := ParseQuestions(data[12:], header.QDCount)

	return &DNS{
		Header:    header,
		Questions: questions,
	}
}

func (dr *DNS) AsQuery() {
	dr.Header.Qr = true
}

func (dr *DNS) AddQuestion(domain string, qType, qClass uint16) {
	q := newQuestion(domain, qType, qClass)
	dr.Questions = append(dr.Questions, q)
	dr.Header.QDCount++
}

func (dr *DNS) AddResourceRecord(domain string, rType, rClass uint16, ttl uint32, ip string) {
	rr := newResourceRecord(domain, rType, rClass, ttl, ip)
	dr.ResourceRecords = append(dr.ResourceRecords, rr)
	dr.Header.ANCount++
}

func (dr *DNS) Serialize() []byte {
	s := []byte{}
	s = append(s, dr.Header.Serialize()...)
	for _, q := range dr.Questions {
		s = append(s, q.Serialize()...)
	}
	for _, rr := range dr.ResourceRecords {
		s = append(s, rr.Serialize()...)
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
		header[2] |= 0b1 << 7
	}
	opcode := dh.OPCode & 0b1111
	header[2] |= opcode << 3

	if dh.AA {
		header[2] |= 0b1 << 2
	}

	if dh.TC {
		header[2] |= 0b1 << 1
	}

	if dh.RD {
		header[2] |= 0b1
	}

	if dh.RA {
		header[3] |= 0b1 << 7
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

func ParseDNSHeader(headerData []byte) *DNSHeader {
	if len(headerData) != 12 {
		error := fmt.Sprintf("headerData len is %d, should be %d", len(headerData), 12)
		panic(error)

	}

	flagPart1 := uint8(headerData[2])

	rd := flagPart1 & 0b1
	flagPart1 >>= 1

	tc := flagPart1 & 0b1
	flagPart1 >>= 1

	aa := flagPart1 & 0b1
	flagPart1 >>= 1

	opcode := flagPart1 & 0b1111
	flagPart1 >>= 4

	qr := flagPart1 & 0b1

	flagPart2 := uint8(headerData[3])

	rCode := flagPart2 & 0b1111
	flagPart2 >>= 4

	z := flagPart2 & 0b111
	flagPart2 >>= 3

	ra := flagPart2 & 0b1

	return &DNSHeader{
		Id:      binary.BigEndian.Uint16(headerData[0:2]),
		Qr:      uint8ToBool(qr),
		OPCode:  opcode,
		AA:      uint8ToBool(aa),
		TC:      uint8ToBool(tc),
		RD:      uint8ToBool(rd),
		RA:      uint8ToBool(ra),
		Z:       z,
		RCode:   rCode,
		QDCount: binary.BigEndian.Uint16(headerData[4:6]),
		ANCount: binary.BigEndian.Uint16(headerData[6:8]),
		NSCount: binary.BigEndian.Uint16(headerData[8:10]),
		ARCount: binary.BigEndian.Uint16(headerData[10:12]),
	}
}

func uint8ToBool(num uint8) bool {
	if num == 1 {
		return true
	} else if num == 0 {
		return false
	}

	panic(fmt.Sprintf("expected num to be 1 or 0, got %d", num))
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func newQuestion(domain string, qType, qClass uint16) *Question {
	return &Question{Name: domain, Type: qType, Class: qClass}
}

func (q *Question) Serialize() []byte {
	serialized := []byte{}
	serialized = append(serialized, ToLabelSequence(q.Name)...)

	serialized = binary.BigEndian.AppendUint16(serialized, q.Type)
	serialized = binary.BigEndian.AppendUint16(serialized, q.Class)

	return serialized
}

func ParseQuestions(data []byte, qdCount uint16) []*Question {
	offsetFromHeader := uint16(12)
	qs := make([]*Question, qdCount)
	token := uint16(0)

	for i := 0; i < int(qdCount); i++ {
		name := ""
		name, token = parseName(data, token, offsetFromHeader)

		types := binary.BigEndian.Uint16(data[token : token+2])
		token += 2
		class := binary.BigEndian.Uint16(data[token : token+2])
		token += 2

		q := &Question{
			Name:  name,
			Type:  types,
			Class: class,
		}

		qs[i] = q
	}

	return qs
}

func parseName(data []byte, startToken, headerOffset uint16) (string, uint16) {
	name := ""
	token := startToken
	i := startToken
	followedPointer := false
	for {
		if data[i] == 0 {
			if !followedPointer {
				token++
			}
			break
		} else if data[i]>>6 == 0b11 {
			pointer := binary.BigEndian.Uint16(data[i : i+2])
			offset := pointer & 0b0011111111111111
			i = offset - headerOffset
			if !followedPointer {
				token += 2
				followedPointer = true
			}
		} else {
			seqLength := uint16(data[i])
			name += string(data[i+1:i + 1 + seqLength ]) + "."

			i += seqLength + 1
			if !followedPointer {
				token += seqLength + 1
			}
		}
	}

	return name, token
}

type ResourceRecord struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

func newResourceRecord(domain string, rType, rClass uint16, ttl uint32, ip string) *ResourceRecord {
	data := ToIpSequence(ip)
	return &ResourceRecord{
		Name:   domain,
		Type:   rType,
		Class:  rClass,
		TTL:    ttl,
		Length: uint16(len(data)),
		Data:   data,
	}
}

func (rr *ResourceRecord) Serialize() []byte {
	serialized := []byte{}
	serialized = append(serialized, ToLabelSequence(rr.Name)...)

	serialized = binary.BigEndian.AppendUint16(serialized, rr.Type)
	serialized = binary.BigEndian.AppendUint16(serialized, rr.Class)
	serialized = binary.BigEndian.AppendUint32(serialized, rr.TTL)
	serialized = binary.BigEndian.AppendUint16(serialized, rr.Length)
	serialized = binary.BigEndian.AppendUint16(serialized, rr.Length)

	if rr.Type == TypeA {
		data := binary.BigEndian.Uint32(rr.Data[:4])
		serialized = binary.BigEndian.AppendUint32(serialized, data)
	}

	return serialized
}

func ToLabelSequence(label string) []byte {
	ls := []byte{}
	parts := strings.Split(label, ".")

	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	for _, part := range parts {
		bs := []byte(part)
		ls = append(ls, byte(len(bs)))
		ls = append(ls, bs...)
	}

	ls = append(ls, 0)
	return ls
}

func ToIpSequence(ip string) []byte {
	bs := make([]byte, 4)
	split := strings.Split(ip, ".")
	for i, s := range split {
		bs[i] = byte(s[0])
	}

	return bs
}

func FromSequence(seq []byte) string {
	bs := []byte{}
	i := 0
	fmt.Printf("Label: %v\n", seq)
	for seq[i] != 0 {
		segLength := int(seq[i])
		i++
		length := segLength + i

		for ; i < length; i++ {
			bs = append(bs, seq[i])
		}

		bs = append(bs, '.')
	}

	return string(bs)
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

		response := dns.Serialize()

		fmt.Printf("Sending %d bytes from %s: %s\n", len(response), source, response)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
