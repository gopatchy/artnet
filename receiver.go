package artnet

import (
	"net"
	"time"
)

type Handler interface {
	HandleDMX(src *net.UDPAddr, pkt *DMXPacket)
	HandlePoll(src *net.UDPAddr, pkt *PollPacket)
	HandlePollReply(src *net.UDPAddr, pkt *PollReplyPacket)
}

type Receiver struct {
	conn    *net.UDPConn
	handler Handler
	done    chan struct{}
}

func NewReceiver(addr *net.UDPAddr, handler Handler) (*Receiver, error) {
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}

	return &Receiver{
		conn:    conn,
		handler: handler,
		done:    make(chan struct{}),
	}, nil
}

func NewDefaultReceiver(handler Handler) (*Receiver, error) {
	return NewReceiver(&net.UDPAddr{Port: Port}, handler)
}

func (r *Receiver) Start() {
	go r.loop()
}

func (r *Receiver) Stop() {
	close(r.done)
	r.conn.Close()
}

func (r *Receiver) Conn() *net.UDPConn {
	return r.conn
}

func (r *Receiver) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

func (r *Receiver) SendTo(data []byte, addr *net.UDPAddr) error {
	_, err := r.conn.WriteToUDP(data, addr)
	return err
}

func (r *Receiver) loop() {
	buf := make([]byte, 1024)

	for {
		select {
		case <-r.done:
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-r.done:
				return
			default:
				continue
			}
		}

		r.handle(src, buf[:n])
	}
}

func (r *Receiver) handle(src *net.UDPAddr, data []byte) {
	opCode, pkt, err := ParsePacket(data)
	if err != nil {
		return
	}

	switch opCode {
	case OpDmx:
		if dmx, ok := pkt.(*DMXPacket); ok {
			r.handler.HandleDMX(src, dmx)
		}
	case OpPoll:
		if poll, ok := pkt.(*PollPacket); ok {
			r.handler.HandlePoll(src, poll)
		}
	case OpPollReply:
		if reply, ok := pkt.(*PollReplyPacket); ok {
			r.handler.HandlePollReply(src, reply)
		}
	}
}
