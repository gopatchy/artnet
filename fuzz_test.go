package artnet

import (
	"bytes"
	"testing"
)

func FuzzParsePacket(f *testing.F) {
	validDMX := BuildDMXPacket(NewUniverse(0, 0, 1), 0, make([]byte, 512))
	f.Add(validDMX)
	f.Add(BuildDMXPacket(NewUniverse(127, 15, 15), 255, make([]byte, 512)))
	f.Add(BuildDMXPacket(NewUniverse(0, 0, 0), 0, make([]byte, 2)))
	f.Add(BuildPollPacket())
	f.Add(BuildPollReplyPacket([4]byte{192, 168, 1, 1}, [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "short", "long name", []Universe{NewUniverse(0, 0, 1)}, false))
	f.Add([]byte{})
	f.Add(make([]byte, 9))
	f.Add(make([]byte, 10))
	f.Add(make([]byte, 17))
	f.Add(make([]byte, 18))
	f.Add(make([]byte, 206))
	f.Add(make([]byte, 207))

	wrongHeader := make([]byte, 100)
	copy(wrongHeader, []byte("Wrong-Ne"))
	f.Add(wrongHeader)

	f.Fuzz(func(t *testing.T, data []byte) {
		opCode, pkt, err := ParsePacket(data)
		if err != nil {
			return
		}
		switch opCode {
		case OpDmx:
			_, ok := pkt.(*DMXPacket)
			if !ok && pkt != nil {
				t.Fatal("OpDmx returned non-DMXPacket")
			}
		case OpPoll:
			_, ok := pkt.(*PollPacket)
			if !ok && pkt != nil {
				t.Fatal("OpPoll returned non-PollPacket")
			}
		case OpPollReply:
			if reply, ok := pkt.(*PollReplyPacket); ok {
				if reply.NumPorts() > 4 {
					t.Fatalf("NumPorts exceeds 4: %d", reply.NumPorts())
				}
			}
		}
	})
}

func FuzzDMXRoundtrip(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), make([]byte, 512))
	f.Add(uint8(127), uint8(15), uint8(15), uint8(255), make([]byte, 512))
	f.Add(uint8(0), uint8(0), uint8(1), uint8(128), make([]byte, 100))
	f.Add(uint8(50), uint8(8), uint8(10), uint8(1), make([]byte, 2))

	f.Fuzz(func(t *testing.T, netVal, subnet, uni, seq uint8, dmxInput []byte) {
		universe := NewUniverse(netVal, subnet, uni)
		packet := BuildDMXPacket(universe, seq, dmxInput)

		opCode, pkt, err := ParsePacket(packet)
		if err != nil {
			t.Fatalf("failed to parse packet we just built: %v", err)
		}
		if opCode != OpDmx {
			t.Fatalf("expected OpDmx, got %d", opCode)
		}
		dmx, ok := pkt.(*DMXPacket)
		if !ok {
			t.Fatal("expected DMXPacket")
		}
		if dmx.Sequence != seq {
			t.Fatalf("sequence mismatch: sent %d, got %d", seq, dmx.Sequence)
		}
		if dmx.Universe != universe {
			t.Fatalf("universe mismatch: sent %v, got %v", universe, dmx.Universe)
		}
		expectedLen := len(dmxInput)
		if expectedLen > 512 {
			expectedLen = 512
		}
		if expectedLen%2 != 0 {
			expectedLen++
		}
		if int(dmx.Length) != expectedLen {
			t.Fatalf("length mismatch: expected %d, got %d", expectedLen, dmx.Length)
		}
		compareLen := len(dmxInput)
		if compareLen > 512 {
			compareLen = 512
		}
		if !bytes.Equal(dmx.Data[:compareLen], dmxInput[:compareLen]) {
			t.Fatal("dmx data mismatch")
		}
	})
}

func FuzzPollReplyRoundtrip(f *testing.F) {
	f.Add([]byte{192, 168, 1, 1}, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "short", "long name", uint8(0), uint8(0), uint8(1), true)
	f.Add([]byte{10, 0, 0, 1}, []byte{0, 0, 0, 0, 0, 0}, "", "", uint8(127), uint8(15), uint8(15), false)

	f.Fuzz(func(t *testing.T, ipSlice, macSlice []byte, shortName, longName string, netVal, subnet, uni uint8, isInput bool) {
		if len(ipSlice) < 4 || len(macSlice) < 6 {
			return
		}
		var ip [4]byte
		var mac [6]byte
		copy(ip[:], ipSlice[:4])
		copy(mac[:], macSlice[:6])

		universe := NewUniverse(netVal, subnet, uni)
		packet := BuildPollReplyPacket(ip, mac, shortName, longName, []Universe{universe}, isInput)

		opCode, pkt, err := ParsePacket(packet)
		if err != nil {
			t.Fatalf("failed to parse packet we just built: %v", err)
		}
		if opCode != OpPollReply {
			t.Fatalf("expected OpPollReply, got %d", opCode)
		}
		reply, ok := pkt.(*PollReplyPacket)
		if !ok {
			t.Fatal("expected PollReplyPacket")
		}
		if reply.IPAddress != ip {
			t.Fatalf("IP mismatch")
		}
		if !bytes.Equal(reply.MAC[:], mac[:]) {
			t.Fatal("MAC mismatch")
		}
	})
}

func FuzzUniverse(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0))
	f.Add(uint8(127), uint8(15), uint8(15))
	f.Add(uint8(50), uint8(8), uint8(10))

	f.Fuzz(func(t *testing.T, netVal, subnet, uni uint8) {
		universe := NewUniverse(netVal, subnet, uni)
		gotNet := universe.Net()
		gotSubnet := universe.SubNet()
		gotUni := universe.Universe()
		expectedNet := netVal & 0x7F
		expectedSubnet := subnet & 0x0F
		expectedUni := uni & 0x0F
		if gotNet != expectedNet {
			t.Fatalf("Net mismatch: input %d, expected %d, got %d", netVal, expectedNet, gotNet)
		}
		if gotSubnet != expectedSubnet {
			t.Fatalf("SubNet mismatch: input %d, expected %d, got %d", subnet, expectedSubnet, gotSubnet)
		}
		if gotUni != expectedUni {
			t.Fatalf("Universe mismatch: input %d, expected %d, got %d", uni, expectedUni, gotUni)
		}
	})
}
