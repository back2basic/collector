package bpfgo

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	// bpfObjPath = "./bpf/sia_bpfel.o"
	bpfObjPath = "/var/lib/collector/bpf/sia_bpfel.o"

	PORT_CONSENSUS = 1
	PORT_SIAMUX    = 2
	PORT_QUIC      = 3
)

type Handles struct {
	Coll      *ebpf.Collection
	IP4Stats  *ebpf.Map
	IP6Stats  *ebpf.Map
	TCLastIP4 *ebpf.Map
	XDPLink   link.Link
	TCLink    link.Link
}

func Load(iface string) (*Handles, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	h := &Handles{Coll: coll}

	// Resolve maps
	ip4Stats, ok := coll.Maps["ip4_stats"]
	if !ok {
		return nil, fmt.Errorf("missing map ip4_stats")
	}
	h.IP4Stats = ip4Stats

	ip6Stats, ok := coll.Maps["ip6_stats"]
	if !ok {
		return nil, fmt.Errorf("missing map ip6_stats")
	}
	h.IP6Stats = ip6Stats

	tcLast, ok := coll.Maps["tc_last_ip4"]
	if !ok {
		return nil, fmt.Errorf("missing map tc_last_ip4")
	}
	h.TCLastIP4 = tcLast

	// Load ports from env into port_config
	if err := loadPorts(coll); err != nil {
		return nil, fmt.Errorf("loadPorts: %w", err)
	}

	// Attach XDP + TC
	if err := attachPrograms(h, iface); err != nil {
		h.Close()
		return nil, err
	}

	return h, nil
}

func loadPorts(coll *ebpf.Collection) error {
	portMap, ok := coll.Maps["port_config"]
	if !ok {
		return fmt.Errorf("port_config map not found in BPF object")
	}

	type entry struct {
		key uint32
		env string
	}

	ports := []entry{
		{PORT_CONSENSUS, "PORT_SIA_CONSENSUS"},
		{PORT_SIAMUX, "PORT_RHP4_SIAMUX"},
		{PORT_QUIC, "PORT_RHP4_QUIC"},
	}

	for _, p := range ports {
		val := os.Getenv(p.env)
		if val == "" {
			continue
		}

		port, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("invalid value for %s: %v", p.env, err)
		}

		k := uint32(p.key)
		v := uint16(port)

		if err := portMap.Put(unsafe.Pointer(&k), unsafe.Pointer(&v)); err != nil {
			return fmt.Errorf("failed to write %s to port_config: %v", p.env, err)
		}
	}

	return nil
}

func attachPrograms(h *Handles, iface string) error {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("lookup iface %s: %w", iface, err)
	}

	xdpProg, ok := h.Coll.Programs["xdp_ingress"]
	if !ok {
		return fmt.Errorf("missing XDP program xdp_ingress")
	}

	tcProg, ok := h.Coll.Programs["tc_egress"]
	if !ok {
		return fmt.Errorf("missing TC program tc_egress")
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: ifaceObj.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attach XDP: %w", err)
	}
	h.XDPLink = xdpLink

	// Attach TC egress
	if err := ensureTCHook(iface); err != nil {
		return fmt.Errorf("ensure tc hook: %w", err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   tcProg,
		Interface: ifaceObj.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach TC: %w", err)
	}
	h.TCLink = tcLink

	return nil
}

// ensureTCHook is a placeholder; if you already have tc qdisc setup logic,
// keep that instead or wire this into your existing helper.
func ensureTCHook(iface string) error {
	// If you already manage qdisc via `tc qdisc add dev ...`, you can no-op here.
	// Or you can shell out / use a netlink lib to ensure clsact exists.
	_ = iface
	return nil
}

func (h *Handles) Close() {
	if h.XDPLink != nil {
		h.XDPLink.Close()
	}
	if h.TCLink != nil {
		h.TCLink.Close()
	}
	if h.Coll != nil {
		h.Coll.Close()
	}
}

// Optional helper if you want to load from a different path in dev
func BPFPath() string {
	if p := os.Getenv("COLLECTOR_BPF_PATH"); p != "" {
		return p
	}
	return filepath.Clean(bpfObjPath)
}
