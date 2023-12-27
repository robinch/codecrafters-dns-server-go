package main

import (
	"fmt"
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

func NewDNS() *DNS {
	h := &DNSHeader{}
	qs := []*Question{}

	return &DNS{Header: h, Questions: qs}
}

func NewResponseDns(reqDns *DNS) *DNS {
	h := &DNSHeader{}
	qs := []*Question{}

	h.Id = reqDns.Header.Id
	h.OPCode = reqDns.Header.OPCode
	h.RD = reqDns.Header.RD
	if h.OPCode == 0 {
		h.RCode = 0
	} else {
		h.RCode = 4
	}
	h.Qr = true

	return &DNS{Header: h, Questions: qs}
}

func NewQueryDns(reqDns *DNS) *DNS {
	h := &DNSHeader{}
	qs := []*Question{}

	h.Id = reqDns.Header.Id
	h.OPCode = reqDns.Header.OPCode
	h.RD = reqDns.Header.RD
	if h.OPCode == 0 {
		h.RCode = 0
	} else {
		h.RCode = 4
	}

	return &DNS{Header: h, Questions: qs}
}

func ParseDNS(data []byte) *DNS {
	header := ParseDNSHeader(data[0:12])
	questions, token := ParseQuestions(data[12:], header.QDCount)
	resourceRecords := ParseResourceRecords(data[token:], header.ANCount)

	return &DNS{
		Header:          header,
		Questions:       questions,
		ResourceRecords: resourceRecords,
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

func (dr *DNS) AddResourceRecord(domain string, rType, rClass uint16, ttl uint32, data []byte) {
	rr := newResourceRecord(domain, rType, rClass, ttl, data)
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

func uint8ToBool(num uint8) bool {
	if num == 1 {
		return true
	} else if num == 0 {
		return false
	}

	panic(fmt.Sprintf("expected num to be 1 or 0, got %d", num))
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
