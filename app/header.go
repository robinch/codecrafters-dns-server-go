package main

import (
	"encoding/binary"
	"fmt"
)

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
