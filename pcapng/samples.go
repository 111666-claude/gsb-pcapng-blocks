package pcapng

// Scenario 是一个固定场景。
type Scenario struct {
	Name string
	Run  func() map[string]any
}

func block(blockType uint32, body []byte) []byte {
	total := 12 + len(body)
	out := []byte{byte(blockType), byte(blockType >> 8), byte(blockType >> 16), byte(blockType >> 24)}
	out = append(out, byte(total), byte(total>>8), byte(total>>16), byte(total>>24))
	out = append(out, body...)
	out = append(out, byte(total), byte(total>>8), byte(total>>16), byte(total>>24))
	return out
}

func option(code, length int, value []byte) []byte {
	out := []byte{byte(code), byte(code >> 8), byte(length), byte(length >> 8)}
	out = append(out, value...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func shb() []byte {
	body := []byte{0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return block(0x0a0d0d0a, body)
}

func epb(payload []byte) []byte {
	body := make([]byte, 20)
	body[12] = byte(len(payload))
	body = append(body, payload...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return block(6, body)
}

func blockBE(blockType uint32, body []byte) []byte {
	total := 12 + len(body)
	out := []byte{byte(blockType >> 24), byte(blockType >> 16), byte(blockType >> 8), byte(blockType)}
	out = append(out, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	out = append(out, body...)
	out = append(out, byte(total>>24), byte(total>>16), byte(total>>8), byte(total))
	return out
}

func shbBE() []byte {
	body := []byte{0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x01, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return blockBE(0x0a0d0d0a, body)
}

func epbBE(payload []byte) []byte {
	body := make([]byte, 20)
	body[15] = byte(len(payload))
	body = append(body, payload...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return blockBE(6, body)
}

// Samples 返回全部场景。
func Samples() []Scenario {
	return []Scenario{
		{Name: "endian", Run: func() map[string]any {
			file, _ := Parse(append(shbBE(), epbBE([]byte{1, 2, 3, 4})...), &Counter{})
			return map[string]any{"packets": len(file.Packets)}
		}},
		{Name: "trailer", Run: func() map[string]any {
			data := append(shb(), epb([]byte{1, 2, 3, 4})...)
			data[len(data)-1] = 0xff
			_, err := Parse(data, &Counter{})
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			return map[string]any{"ok": true}
		}},
		{Name: "pad", Run: func() map[string]any {
			opts := option(2, 3, []byte("abc"))
			opts = append(opts, option(3, 1, []byte("z"))...)
			file, _ := Parse(append(shb(), block(1, append([]byte{1, 0, 0, 0, 0xff, 0xff, 0, 0}, opts...))...), &Counter{})
			if value, ok := file.Options[3]; ok {
				return map[string]any{"opt3": string(value)}
			}
			return map[string]any{"opt3": ""}
		}},
		{Name: "endopt", Run: func() map[string]any {
			opts := option(1, 4, []byte("abcd"))
			opts = append(opts, option(0, 0, nil)...)
			opts = append(opts, 0x59, 0x59, 0, 0)
			file, _ := Parse(append(shb(), block(1, append([]byte{1, 0, 0, 0, 0xff, 0xff, 0, 0}, opts...))...), &Counter{})
			_, ok := file.Options[0x5959]
			return map[string]any{"bogus": ok}
		}},
	}
}

// Work 跑规模线场景。
func Work(n int) map[string]any {
	var data []byte
	for i := 0; i < n; i++ {
		data = append(data, block(0x0bad, make([]byte, 4))...)
	}
	c := &Counter{}
	for i := 0; i < n; i++ {
		BlockAt(data, i, c)
	}
	return map[string]any{"blocks": n, "scanned": c.Scanned}
}
