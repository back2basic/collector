package model

type TrafficRecord4 struct {
	Key           uint32
	IP            string
	DNS           string
	ConsensusUp   uint64
	ConsensusDown uint64
	SiamuxUp      uint64
	SiamuxDown    uint64
	QuicUp        uint64
	QuicDown      uint64
	Timestamp     int64
}

type TrafficRecord6 struct {
	Key           [16]byte
	IP            string
	DNS           string
	ConsensusUp   uint64
	ConsensusDown uint64
	SiamuxUp      uint64
	SiamuxDown    uint64
	QuicUp        uint64
	QuicDown      uint64
	Timestamp     int64
}

type AggregatedRecord struct {
	IP            string
	DNS           string
	ConsensusUp   uint64
	ConsensusDown uint64
	SiamuxUp      uint64
	SiamuxDown    uint64
	QuicUp        uint64
	QuicDown      uint64
}
