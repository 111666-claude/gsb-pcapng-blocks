package pcapng

import "testing"

func TestParseShb(t *testing.T) {
	file, err := Parse(shb(), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(file.Packets) != 0 {
		t.Fatalf("SHB 不该产生包：%d", len(file.Packets))
	}
}

func TestShortData(t *testing.T) {
	file, err := Parse([]byte{1, 2, 3}, &Counter{})
	if err != nil || len(file.Packets) != 0 {
		t.Fatalf("过短数据不该报错：%v", err)
	}
}

func TestBlockAtZero(t *testing.T) {
	block, err := BlockAt(shb(), 0, &Counter{})
	if err != nil || len(block) == 0 {
		t.Fatalf("取第 0 块失败：%v", err)
	}
}

func TestBlockAtOutOfRange(t *testing.T) {
	if _, err := BlockAt(shb(), 9, &Counter{}); err == nil {
		t.Fatal("越界应报错")
	}
}

func TestOptionsStored(t *testing.T) {
	opts := option(2, 1, []byte("a"))
	body := append([]byte{1, 0, 0, 0, 0xff, 0xff, 0, 0}, opts...)
	file, _ := Parse(append(shb(), block(1, body)...), &Counter{})
	if string(file.Options[2]) != "a" {
		t.Fatalf("选项 2 应是 a：%q", file.Options[2])
	}
}

func TestCounterCounts(t *testing.T) {
	c := &Counter{}
	Parse(shb(), c)
	if c.Scanned == 0 {
		t.Fatal("应统计比较次数")
	}
}
