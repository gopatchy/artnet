package artnet

import (
	"context"
	"net"
	"sync"
	"syscall"
)

type Sender struct {
	conn      *net.UDPConn
	sequences map[Universe]uint8
	seqMu     sync.Mutex
}

func NewSender() (*Sender, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	return &Sender{
		conn:      conn,
		sequences: map[Universe]uint8{},
	}, nil
}

func NewSenderFromConn(conn *net.UDPConn) *Sender {
	return &Sender{
		conn:      conn,
		sequences: map[Universe]uint8{},
	}
}

func NewInterfaceSender(ifaceName string) (*Sender, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
			})
			return err
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return nil, err
	}

	return &Sender{
		conn:      conn.(*net.UDPConn),
		sequences: map[Universe]uint8{},
	}, nil
}

func (s *Sender) SendDMX(addr *net.UDPAddr, universe Universe, data []byte) error {
	s.seqMu.Lock()
	seq := s.sequences[universe]
	seq++
	if seq == 0 {
		seq = 1
	}
	s.sequences[universe] = seq
	s.seqMu.Unlock()

	pkt := BuildDMXPacket(universe, seq, data)
	_, err := s.conn.WriteToUDP(pkt, addr)
	return err
}

func (s *Sender) SendPoll(addr *net.UDPAddr) error {
	pkt := BuildPollPacket()
	_, err := s.conn.WriteToUDP(pkt, addr)
	return err
}

func (s *Sender) SendPollReply(addr *net.UDPAddr, localIP [4]byte, localMAC [6]byte, shortName, longName string, universes []Universe, isInput bool) error {
	pkt := BuildPollReplyPacket(localIP, localMAC, shortName, longName, universes, isInput)
	_, err := s.conn.WriteToUDP(pkt, addr)
	return err
}

func (s *Sender) SendRaw(addr *net.UDPAddr, data []byte) error {
	_, err := s.conn.WriteToUDP(data, addr)
	return err
}

func (s *Sender) Close() error {
	return s.conn.Close()
}

func (s *Sender) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}
