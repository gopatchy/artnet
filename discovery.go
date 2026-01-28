package artnet

import (
	"net"
	"sync"
	"time"
)

type Node struct {
	IP          net.IP
	Port        uint16
	MAC         net.HardwareAddr
	ShortName   string
	LongName    string
	Inputs      []Universe
	Outputs     []Universe
	LastSeen    time.Time
}

type Discovery struct {
	sender       *Sender
	receiver     *Receiver
	nodes        map[string]*Node
	nodesMu      sync.RWMutex
	localIP      [4]byte
	localMAC     [6]byte
	broadcast    net.IP
	shortName    string
	longName     string
	inputUnivs   []Universe
	outputUnivs  []Universe
	pollTargets  []*net.UDPAddr
	done         chan struct{}
	onChange     func(*Node)
}

func NewDiscovery(sender *Sender, shortName, longName string, inputUnivs, outputUnivs []Universe, pollTargets []*net.UDPAddr) *Discovery {
	return &Discovery{
		sender:      sender,
		nodes:       map[string]*Node{},
		shortName:   shortName,
		longName:    longName,
		inputUnivs:  inputUnivs,
		outputUnivs: outputUnivs,
		pollTargets: pollTargets,
		done:        make(chan struct{}),
	}
}

func (d *Discovery) Start() {
	d.detectInterface()
	go d.pollLoop()
}

func (d *Discovery) Stop() {
	close(d.done)
}

func (d *Discovery) SetReceiver(r *Receiver) {
	d.receiver = r
}

func (d *Discovery) SetOnChange(fn func(*Node)) {
	d.onChange = fn
}

func (d *Discovery) pollLoop() {
	d.sendPolls()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			d.sendPolls()
		case <-cleanupTicker.C:
			d.cleanup()
		}
	}
}

func (d *Discovery) sendPolls() {
	for _, target := range d.pollTargets {
		d.sender.SendPoll(target)
	}
}

func (d *Discovery) cleanup() {
	d.nodesMu.Lock()
	defer d.nodesMu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	for ip, node := range d.nodes {
		if node.LastSeen.Before(cutoff) {
			delete(d.nodes, ip)
		}
	}
}

func (d *Discovery) HandlePollReply(src *net.UDPAddr, pkt *PollReplyPacket) {
	d.nodesMu.Lock()
	defer d.nodesMu.Unlock()

	ip := src.IP.String()

	localIP := net.IP(d.localIP[:])
	if src.IP.Equal(localIP) {
		return
	}

	node, exists := d.nodes[ip]
	if !exists {
		node = &Node{
			IP:   src.IP,
			Port: pkt.Port,
		}
		d.nodes[ip] = node
	}

	node.ShortName = pkt.GetShortName()
	node.LongName = pkt.GetLongName()
	node.MAC = pkt.MACAddr()
	node.LastSeen = time.Now()

	for _, u := range pkt.InputUniverses() {
		if !containsUniverse(node.Inputs, u) {
			node.Inputs = append(node.Inputs, u)
		}
	}
	for _, u := range pkt.OutputUniverses() {
		if !containsUniverse(node.Outputs, u) {
			node.Outputs = append(node.Outputs, u)
		}
	}

	if d.onChange != nil {
		d.onChange(node)
	}
}

func (d *Discovery) HandlePoll(src *net.UDPAddr) {
	if d.receiver == nil {
		return
	}
	dst := &net.UDPAddr{IP: d.broadcast, Port: Port}
	d.sendPollReplies(dst, d.inputUnivs, true)
	d.sendPollReplies(dst, d.outputUnivs, false)
}

func (d *Discovery) sendPollReplies(dst *net.UDPAddr, universes []Universe, isInput bool) {
	groups := map[uint16][]Universe{}
	for _, u := range universes {
		key := uint16(u.Net())<<8 | uint16(u.SubNet())<<4
		groups[key] = append(groups[key], u)
	}

	for _, univs := range groups {
		for i := 0; i < len(univs); i += 4 {
			end := i + 4
			if end > len(univs) {
				end = len(univs)
			}
			chunk := univs[i:end]
			pkt := BuildPollReplyPacket(d.localIP, d.localMAC, d.shortName, d.longName, chunk, isInput)
			d.receiver.SendTo(pkt, dst)
		}
	}
}

func (d *Discovery) GetNodesForUniverse(universe Universe) []*Node {
	d.nodesMu.RLock()
	defer d.nodesMu.RUnlock()

	var result []*Node
	for _, node := range d.nodes {
		for _, u := range node.Outputs {
			if u == universe {
				result = append(result, node)
				break
			}
		}
	}
	return result
}

func (d *Discovery) GetAllNodes() []*Node {
	d.nodesMu.RLock()
	defer d.nodesMu.RUnlock()

	result := make([]*Node, 0, len(d.nodes))
	for _, node := range d.nodes {
		result = append(result, node)
	}
	return result
}

func (d *Discovery) SetLocalIP(ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		copy(d.localIP[:], ip4)
	}
}

func (d *Discovery) detectInterface() {
	d.broadcast = net.IPv4bcast

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}

			copy(d.localIP[:], ip4)

			if len(iface.HardwareAddr) == 6 {
				copy(d.localMAC[:], iface.HardwareAddr)
			}

			bcast := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				bcast[i] = ip4[i] | ^ipnet.Mask[i]
			}
			d.broadcast = bcast
			return
		}
	}
}

func containsUniverse(slice []Universe, val Universe) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
