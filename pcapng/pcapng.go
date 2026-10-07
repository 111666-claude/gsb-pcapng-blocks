// Package pcapng 解析 pcapng 文件。
package pcapng

import (
	"encoding/binary"
	"errors"
)

// Counter 记录比较次数。
type Counter struct {
	Scanned int
}

// Packet 是一个抓包。
type Packet struct {
	Iface int
	TS    int64
	Data  []byte
}

// File 是解析结果。
type File struct {
	BigEndian bool
	LinkType  int
	Snaplen   int
	Packets   []Packet
	Options   map[int][]byte
}

func readU16(b []byte) int {
	return int(b[0]) | int(b[1])<<8
}

func readU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// Parse 解析整份文件。
func Parse(data []byte, c *Counter) (*File, error) {
	file := &File{Options: map[int][]byte{}}
	pos := 0
	for pos+12 <= len(data) {
		c.Scanned++
		blockType := readU32(data[pos:])
		total := int(readU32(data[pos+4:]))
		if total < 12 || pos+total > len(data) {
			break
		}
		body := data[pos+8 : pos+total-4]
		if blockType == 0x0a0d0d0a {
			if len(body) >= 4 {
				magic := readU32(body)
				file.BigEndian = magic == 0x1a2b3c4d
			}
			parseOptions(file, body[16:], c)
		} else if blockType == 1 {
			if len(body) >= 8 {
				file.LinkType = readU16(body)
				file.Snaplen = int(readU32(body[4:]))
			}
			parseOptions(file, body[8:], c)
		} else if blockType == 6 {
			if len(body) >= 20 {
				caplen := int(readU32(body[12:]))
				start := 20
				if start+caplen <= len(body) {
					file.Packets = append(file.Packets, Packet{
						Iface: int(readU32(body)),
						TS:    int64(readU32(body[4:]))<<32 | int64(readU32(body[8:])),
						Data:  append([]byte(nil), body[start:start+caplen]...),
					})
				}
				parseOptions(file, body[start+caplen:], c)
			}
		}
		pos += total
	}
	return file, nil
}

func parseOptions(file *File, data []byte, c *Counter) {
	i := 0
	for i+4 <= len(data) {
		c.Scanned++
		code := readU16(data[i:])
		length := readU16(data[i+2:])
		i += 4
		if i+length > len(data) {
			break
		}
		file.Options[code] = append([]byte(nil), data[i:i+length]...)
		i += length
	}
}

// BlockAt 取第 i 个块。
func BlockAt(data []byte, i int, c *Counter) ([]byte, error) {
	pos := 0
	for n := 0; n < i; n++ {
		if pos+12 > len(data) {
			return nil, errors.New("out-of-range")
		}
		for k := 0; k < 4; k++ {
			c.Scanned++
		}
		total := int(readU32(data[pos+4:]))
		if total < 12 {
			return nil, errors.New("bad-length")
		}
		pos += total
	}
	if pos+12 > len(data) {
		return nil, errors.New("out-of-range")
	}
	total := int(readU32(data[pos+4:]))
	if pos+total > len(data) {
		return nil, errors.New("out-of-range")
	}
	return data[pos : pos+total], nil
}

var _ = binary.LittleEndian
