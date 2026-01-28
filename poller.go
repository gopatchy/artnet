package artnet

import (
	"net"
	"time"
)

type Poller struct {
	sender   *Sender
	targets  []*net.UDPAddr
	interval time.Duration
	done     chan struct{}
}

func NewPoller(sender *Sender, targets []*net.UDPAddr, interval time.Duration) *Poller {
	return &Poller{
		sender:   sender,
		targets:  targets,
		interval: interval,
		done:     make(chan struct{}),
	}
}

func NewBroadcastPoller(sender *Sender, interval time.Duration) *Poller {
	return &Poller{
		sender:   sender,
		targets:  []*net.UDPAddr{{IP: net.IPv4bcast, Port: Port}},
		interval: interval,
		done:     make(chan struct{}),
	}
}

func (p *Poller) Start() {
	go p.loop()
}

func (p *Poller) Stop() {
	close(p.done)
}

func (p *Poller) Poll() {
	for _, target := range p.targets {
		p.sender.SendPoll(target)
	}
}

func (p *Poller) loop() {
	p.Poll()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.Poll()
		}
	}
}

func (p *Poller) SetTargets(targets []*net.UDPAddr) {
	p.targets = targets
}

func (p *Poller) AddTarget(target *net.UDPAddr) {
	p.targets = append(p.targets, target)
}

func BroadcastAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4bcast, Port: Port}
}

func UnicastAddr(ip net.IP) *net.UDPAddr {
	return &net.UDPAddr{IP: ip, Port: Port}
}

func InterfaceBroadcast(iface net.Interface) *net.UDPAddr {
	addrs, err := iface.Addrs()
	if err != nil {
		return BroadcastAddr()
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

		bcast := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			bcast[i] = ip4[i] | ^ipnet.Mask[i]
		}
		return &net.UDPAddr{IP: bcast, Port: Port}
	}

	return BroadcastAddr()
}
