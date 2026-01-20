package dns


import (
    "net"
    "sync"
    "time"
)

type entry struct {
    name string
    exp  time.Time
}

var (
    mu    sync.Mutex
    cache = make(map[string]entry)
    ttl   = 10 * time.Minute
)

func Resolve(ip net.IP) string {
    s := ip.String()

    mu.Lock()
    if e, ok := cache[s]; ok && time.Now().Before(e.exp) {
        name := e.name
        mu.Unlock()
        return name
    }
    mu.Unlock()

    names, err := net.LookupAddr(s)
    if err != nil || len(names) == 0 {
        mu.Lock()
        cache[s] = entry{"", time.Now().Add(ttl)}
        mu.Unlock()
        return ""
    }

    name := names[0]
    mu.Lock()
    cache[s] = entry{name, time.Now().Add(ttl)}
    mu.Unlock()
    return name
}
