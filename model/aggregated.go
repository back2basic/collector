package model

type AggregatedRecord struct {
	IP          string
	DNS         string
	Up9981      uint64
	Down9981    uint64
	Up9984TCP   uint64
	Down9984TCP uint64
	Up9984UDP   uint64
	Down9984UDP uint64
}
