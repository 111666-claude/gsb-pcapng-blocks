// Package pcapng 解析 pcapng 文件。
package pcapng

import (
	"encoding/binary"
	"errors"
	"reflect"
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

const (
	blockTypeSHB = 0x0a0d0d0a
	blockTypeIDB = 1
	blockTypeEPB = 6

	magicBigEndian    = 0x1a2b3c4d
	magicLittleEndian = 0x4d3c2b1a
)

var errBadLength = errors.New("bad-length")

// byteOrder 按 SHB 块体开头的字节序魔数判断整份文件的字节序。
func byteOrder(data []byte) binary.ByteOrder {
	if len(data) >= 12 && binary.LittleEndian.Uint32(data) == blockTypeSHB {
		switch binary.BigEndian.Uint32(data[8:]) {
		case magicBigEndian:
			return binary.BigEndian
		case magicLittleEndian:
			return binary.LittleEndian
		}
	}
	return binary.LittleEndian
}

// pad4 把 n 向上补齐到 4 的倍数。
func pad4(n int) int {
	return (n + 3) &^ 3
}

// Parse 解析整份文件。
func Parse(data []byte, c *Counter) (*File, error) {
	order := byteOrder(data)
	file := &File{BigEndian: order == binary.BigEndian, Options: map[int][]byte{}}
	pos := 0
	for pos+12 <= len(data) {
		c.Scanned++
		blockType := order.Uint32(data[pos:])
		total := int(order.Uint32(data[pos+4:]))
		if total < 12 || pos+total > len(data) {
			break
		}
		if int(order.Uint32(data[pos+total-4:])) != total {
			return nil, errBadLength
		}
		body := data[pos+8 : pos+total-4]
		switch blockType {
		case blockTypeSHB:
			parseOptions(file, body[16:], order, c)
		case blockTypeIDB:
			if len(body) >= 8 {
				file.LinkType = int(order.Uint16(body))
				file.Snaplen = int(order.Uint32(body[4:]))
			}
			parseOptions(file, body[8:], order, c)
		case blockTypeEPB:
			if len(body) >= 20 {
				caplen := int(order.Uint32(body[12:]))
				start := 20
				if start+caplen <= len(body) {
					file.Packets = append(file.Packets, Packet{
						Iface: int(order.Uint32(body)),
						TS:    int64(order.Uint32(body[4:]))<<32 | int64(order.Uint32(body[8:])),
						Data:  append([]byte(nil), body[start:start+caplen]...),
					})
				}
				if optStart := start + pad4(caplen); optStart <= len(body) {
					parseOptions(file, body[optStart:], order, c)
				}
			}
		}
		pos += total
	}
	return file, nil
}

func parseOptions(file *File, data []byte, order binary.ByteOrder, c *Counter) {
	i := 0
	for i+4 <= len(data) {
		c.Scanned++
		code := order.Uint16(data[i:])
		length := int(order.Uint16(data[i+2:]))
		if code == 0 {
			return
		}
		i += 4
		if i+length > len(data) {
			return
		}
		file.Options[int(code)] = append([]byte(nil), data[i:i+length]...)
		i += pad4(length)
	}
}

// blockIndex 缓存一份数据的块偏移，按块号取块不重扫前面的块的偏移。
type blockIndex struct {
	order   binary.ByteOrder
	offsets []int
}

var (
	indexMu    sync.Mutex
	indexCache = map[[2]uintptr]*blockIndex{}
)

func indexKey(data []byte) [2]uintptr {
	h := (*reflect.SliceHeader)(reflect.ValueOf(&data).UnsafePointer())
	return [2]uintptr{h.Data, uintptr(h.Len)}
}

func indexFor(data []byte) *blockIndex {
	key := indexKey(data)
	indexMu.Lock()
	defer indexMu.Unlock()
	if idx, ok := indexCache[key]; ok {
		return idx
	}
	idx := &blockIndex{order: byteOrder(data)}
	indexCache[key] = idx
	return idx
}

// extend 把索引扩展到第 i 个块（含），返回是否成功。
func (idx *blockIndex) extend(data []byte, i int, c *Counter) bool {
	pos := 0
	if n := len(idx.offsets); n > 0 {
		pos = idx.offsets[n-1] + int(idx.order.Uint32(data[idx.offsets[n-1]+4:]))
	}
	for len(idx.offsets) <= i {
		if pos+12 > len(data) {
			return false
		}
		c.Scanned++
		total := int(idx.order.Uint32(data[pos+4:]))
		if total < 12 || pos+total > len(data) {
			return false
		}
		idx.offsets = append(idx.offsets, pos)
		pos += total
	}
	return true
}

// BlockAt 取第 i 个块。
func BlockAt(data []byte, i int, c *Counter) ([]byte, error) {
	if i < 0 {
		return nil, errors.New("out-of-range")
	}
	idx := indexFor(data)
	indexMu.Lock()
	defer indexMu.Unlock()
	if !idx.extend(data, i, c) {
		return nil, errors.New("out-of-range")
	}
	pos := idx.offsets[i]
	total := int(idx.order.Uint32(data[pos+4:]))
	return data[pos : pos+total], nil
}
