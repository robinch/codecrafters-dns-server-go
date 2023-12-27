package main

import "encoding/binary"

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
