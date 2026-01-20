package model

type TrafficRecord4 struct {
    Key         uint32
    IP          string
    DNS         string
    Up9981      uint64
    Down9981    uint64
    Up9984TCP   uint64
    Down9984TCP uint64
    Up9984UDP   uint64
    Down9984UDP uint64
    Timestamp   int64
}

type TrafficRecord6 struct {
    Key         [16]byte
    IP          string
    DNS         string
    Up9981      uint64
    Down9981    uint64
    Up9984TCP   uint64
    Down9984TCP uint64
    Up9984UDP   uint64
    Down9984UDP uint64
    Timestamp   int64
}
