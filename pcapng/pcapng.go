// Package pcapng 解析 pcapng 文件。
package pcapng

import (
	"encoding/binary"
	"errors"
	"sync"
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

const shbType = 0x0a0d0d0a

// Parse 解析整份文件。
func Parse(data []byte, c *Counter) (*File, error) {
	file := &File{Options: map[int][]byte{}}
	var order binary.ByteOrder = binary.LittleEndian
	pos := 0
	for pos+12 <= len(data) {
		c.Scanned++
		blockType := order.Uint32(data[pos:])
		if blockType == shbType {
			// SHB 块体开头的字节序魔数决定整份文件的字节序。
			switch magic := binary.LittleEndian.Uint32(data[pos+8:]); magic {
			case 0x1a2b3c4d:
				order = binary.LittleEndian
				file.BigEndian = false
			case 0x4d3c2b1a:
				order = binary.BigEndian
				file.BigEndian = true
			}
		}
		total := int(order.Uint32(data[pos+4:]))
		if total < 12 || pos+total > len(data) {
			break
		}
		if order.Uint32(data[pos+total-4:]) != uint32(total) {
			return nil, errors.New("bad-length")
		}
		body := data[pos+8 : pos+total-4]
		switch blockType {
		case shbType:
			if len(body) >= 16 {
				parseOptions(file, order, body[16:], c)
			}
		case 1:
			if len(body) >= 8 {
				file.LinkType = int(order.Uint16(body))
				file.Snaplen = int(order.Uint32(body[4:]))
				parseOptions(file, order, body[8:], c)
			}
		case 6:
			if len(body) >= 20 {
				caplen := int(order.Uint32(body[12:]))
				start := 20
				if start+caplen <= len(body) {
					file.Packets = append(file.Packets, Packet{
						Iface: int(order.Uint32(body)),
						TS:    int64(order.Uint32(body[4:]))<<32 | int64(order.Uint32(body[8:])),
						Data:  append([]byte(nil), body[start:start+caplen]...),
					})
					if opts := start + (caplen+3)&^3; opts <= len(body) {
						parseOptions(file, order, body[opts:], c)
					}
				}
			}
		}
		pos += total
	}
	return file, nil
}

func parseOptions(file *File, order binary.ByteOrder, data []byte, c *Counter) {
	i := 0
	for i+4 <= len(data) {
		c.Scanned++
		code := int(order.Uint16(data[i:]))
		length := int(order.Uint16(data[i+2:]))
		i += 4
		if code == 0 {
			return
		}
		if i+length > len(data) {
			return
		}
		file.Options[code] = append([]byte(nil), data[i:i+length]...)
		i += (length + 3) &^ 3
	}
}

var blockIndex = struct {
	sync.Mutex
	data    []byte
	offsets []int
}{}

// BlockAt 取第 i 个块。
func BlockAt(data []byte, i int, c *Counter) ([]byte, error) {
	if i < 0 {
		return nil, errors.New("out-of-range")
	}
	blockIndex.Lock()
	defer blockIndex.Unlock()
	if len(blockIndex.data) != len(data) || (len(data) > 0 && &blockIndex.data[0] != &data[0]) {
		blockIndex.data = data
		blockIndex.offsets = []int{0}
	}
	for len(blockIndex.offsets) <= i {
		pos := blockIndex.offsets[len(blockIndex.offsets)-1]
		if pos+12 > len(data) {
			return nil, errors.New("out-of-range")
		}
		for k := 0; k < 4; k++ {
			c.Scanned++
		}
		total := int(binary.LittleEndian.Uint32(data[pos+4:]))
		if total < 12 || pos+total > len(data) {
			return nil, errors.New("bad-length")
		}
		blockIndex.offsets = append(blockIndex.offsets, pos+total)
	}
	pos := blockIndex.offsets[i]
	if pos+12 > len(data) {
		return nil, errors.New("out-of-range")
	}
	total := int(binary.LittleEndian.Uint32(data[pos+4:]))
	if pos+total > len(data) {
		return nil, errors.New("out-of-range")
	}
	return data[pos : pos+total], nil
}
