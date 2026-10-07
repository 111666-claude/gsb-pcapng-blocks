# pcapng-blocks

解析 pcapng 抓包文件：块链、SHB 里的字节序、块尾长度校验、选项的 4 字节对齐与结束标记。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/pcapng --sample=endian
go run ./cmd/pcapng --sample=trailer
go run ./cmd/pcapng --sample=pad
go run ./cmd/pcapng --sample=endopt
go run ./cmd/pcapng --sample=work
```

## 口径

- **块**：`类型(4) + 总长(4) + 块体 + 总长(4)`，两处总长必须一致，不一致报 `bad-length`。
- **字节序**：SHB 块体开头的字节序魔数（`1A 2B 3C 4D` 或字节反序）决定整份文件的字节序。
- **选项**：每项是 `代码(2) + 长度(2) + 值`，值补齐到 4 字节；代码 0（opt_endofopt）表示选项结束。
- **包**：EPB 块给出接口号、时间戳高低位、抓取长度与数据。
- **索引**：按块号取块不重扫前面的块。

## 不变量

- 解析成功时每个块前后两处总长一致。
- 选项值按 4 字节对齐读取，代码 0 之后不再有选项。
- `scanned` 不随块数乘查询次数放大：两百个块取两百次的 `scanned` 不超过 6000。

## 输出契约

`File` 含字节序、接口信息、包列表与选项。场景打印一行 JSON。
`--sample=work` 打印 `{"blocks": N, "scanned": N}`。
