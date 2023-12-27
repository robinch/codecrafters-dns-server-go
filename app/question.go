package main

import "encoding/binary"

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

func ParseQuestions(data []byte, qdCount uint16) ([]*Question, uint16) {
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

	return qs, token + offsetFromHeader
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
			name += string(data[i+1:i+1+seqLength]) + "."

			i += seqLength + 1
			if !followedPointer {
				token += seqLength + 1
			}
		}
	}

	return name, token
}
