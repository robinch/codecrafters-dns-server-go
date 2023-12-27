package main

import (
	"encoding/binary"
	"fmt"
)

type ResourceRecord struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   []byte
}

func newResourceRecord(domain string, rType, rClass uint16, ttl uint32, data []byte) *ResourceRecord {
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

	if rr.Type == TypeA {
		data := binary.BigEndian.Uint32(rr.Data[:4])
		serialized = binary.BigEndian.AppendUint32(serialized, data)
	}

	return serialized
}

func ParseResourceRecords(data []byte, anCount uint16) []*ResourceRecord {
	offsetFromHeader := uint16(12)
	rrs := make([]*ResourceRecord, anCount)
	token := uint16(0)

	for i := 0; i < int(anCount); i++ {
		name := ""
		name, token = parseName(data, token, offsetFromHeader)
		fmt.Printf("rr name %s\n", name)


		types := binary.BigEndian.Uint16(data[token : token+2])
		token += 2
		class := binary.BigEndian.Uint16(data[token : token+2])
		token += 2
		ttl := binary.BigEndian.Uint32(data[token : token+4])
		token += 4
		length := binary.BigEndian.Uint16(data[token : token+2])
		fmt.Printf("rr length %d\n", length)
		token += 2
		rData := data[token:token+length]
		fmt.Printf("rr data %s\n", data)

		rr := &ResourceRecord{
			Name:  name,
			Type:  types,
			Class: class,
			TTL: ttl,
			Length: length,
			Data: rData,
		}

		rrs[i] = rr
	}

	return rrs
}
