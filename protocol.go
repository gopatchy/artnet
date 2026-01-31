package artnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	Port            = 6454
	ProtocolVersion = 14

	OpPoll       uint16 = 0x2000
	OpPollReply  uint16 = 0x2100
	OpDmx        uint16 = 0x5000
	OpSync       uint16 = 0x5200
	OpAddress    uint16 = 0x6000
	OpInput      uint16 = 0x7000
	OpTodRequest uint16 = 0x8000
	OpTodData    uint16 = 0x8100
	OpTodControl uint16 = 0x8200
	OpRdm        uint16 = 0x8300

	PortTypeOutput uint8 = 0x80
	PortTypeInput  uint8 = 0x40

	GoodOutputDataTransmitted uint8 = 0x80
	GoodInputDataReceived     uint8 = 0x80

	TodCommandFull uint8 = 0x00

	StyleNode       uint8 = 0x00
	StyleController uint8 = 0x01
	StyleMedia      uint8 = 0x02
	StyleRoute      uint8 = 0x03
	StyleBackup     uint8 = 0x04
	StyleConfig     uint8 = 0x05
	StyleVisual     uint8 = 0x06
)

var (
	ID = [8]byte{'A', 'r', 't', '-', 'N', 'e', 't', 0x00}

	ErrInvalidHeader  = errors.New("invalid Art-Net header")
	ErrPacketTooShort = errors.New("packet too short")
)

type Universe uint16

func NewUniverse(netVal, subnet, universe uint8) Universe {
	return Universe((uint16(netVal&0x7F) << 8) | (uint16(subnet&0x0F) << 4) | uint16(universe&0x0F))
}

func (u Universe) Net() uint8     { return uint8((u >> 8) & 0x7F) }
func (u Universe) SubNet() uint8  { return uint8((u >> 4) & 0x0F) }
func (u Universe) Universe() uint8 { return uint8(u & 0x0F) }
func (u Universe) String() string { return fmt.Sprintf("%d.%d.%d", u.Net(), u.SubNet(), u.Universe()) }

type DMXPacket struct {
	ProtocolVersion uint16
	Sequence        uint8
	Physical        uint8
	Universe        Universe
	Length          uint16
	Data            [512]byte
}

type PollPacket struct {
	ProtocolVersion uint16
	Flags           uint8
	DiagPriority    uint8
}

type PollReplyPacket struct {
	IPAddress   [4]byte
	Port        uint16
	VersionInfo uint16
	NetSwitch   uint8
	SubSwitch   uint8
	OemHi       uint8
	Oem         uint8
	UbeaVersion uint8
	Status1     uint8
	EstaMan     uint16
	ShortName   [18]byte
	LongName    [64]byte
	NodeReport  [64]byte
	NumPortsHi  uint8
	NumPortsLo  uint8
	PortTypes   [4]byte
	GoodInput   [4]byte
	GoodOutput  [4]byte
	SwIn        [4]byte
	SwOut       [4]byte
	SwVideo     uint8
	SwMacro     uint8
	SwRemote    uint8
	Style       uint8
	MAC         [6]byte
	BindIP      [4]byte
	BindIndex   uint8
	Status2     uint8
}

func (p *PollReplyPacket) IP() net.IP {
	return net.IPv4(p.IPAddress[0], p.IPAddress[1], p.IPAddress[2], p.IPAddress[3])
}

func (p *PollReplyPacket) MACAddr() net.HardwareAddr {
	return net.HardwareAddr(p.MAC[:])
}

func (p *PollReplyPacket) GetShortName() string {
	return strings.TrimRight(string(p.ShortName[:]), "\x00")
}

func (p *PollReplyPacket) GetLongName() string {
	return strings.TrimRight(string(p.LongName[:]), "\x00")
}

func (p *PollReplyPacket) NumPorts() int {
	n := int(p.NumPortsLo)
	if n > 4 {
		n = 4
	}
	return n
}

func (p *PollReplyPacket) InputUniverses() []Universe {
	var result []Universe
	for i := 0; i < p.NumPorts(); i++ {
		if p.PortTypes[i]&PortTypeInput != 0 {
			u := NewUniverse(p.NetSwitch, p.SubSwitch, p.SwIn[i])
			result = append(result, u)
		}
	}
	return result
}

func (p *PollReplyPacket) OutputUniverses() []Universe {
	var result []Universe
	for i := 0; i < p.NumPorts(); i++ {
		if p.PortTypes[i]&PortTypeOutput != 0 {
			u := NewUniverse(p.NetSwitch, p.SubSwitch, p.SwOut[i])
			result = append(result, u)
		}
	}
	return result
}

type RDMUID [6]byte

func (u RDMUID) Manufacturer() uint16 {
	return uint16(u[0])<<8 | uint16(u[1])
}

func (u RDMUID) Device() uint32 {
	return uint32(u[2])<<24 | uint32(u[3])<<16 | uint32(u[4])<<8 | uint32(u[5])
}

func (u RDMUID) String() string {
	return fmt.Sprintf("%04x:%08x", u.Manufacturer(), u.Device())
}

type TodDataPacket struct {
	RdmVer      uint8
	Port        uint8
	BindIndex   uint8
	Net         uint8
	Command     uint8
	Universe    Universe
	UidTotal    uint16
	BlockCount  uint8
	UidCount    uint8
	UIDs        []RDMUID
}

func ParsePacket(data []byte) (uint16, interface{}, error) {
	if len(data) < 10 {
		return 0, nil, ErrPacketTooShort
	}

	if !bytes.Equal(data[:8], ID[:]) {
		return 0, nil, ErrInvalidHeader
	}

	opCode := binary.LittleEndian.Uint16(data[8:10])

	switch opCode {
	case OpDmx:
		pkt, err := parseDMXPacket(data)
		return opCode, pkt, err
	case OpPoll:
		pkt, err := parsePollPacket(data)
		return opCode, pkt, err
	case OpPollReply:
		pkt, err := parsePollReplyPacket(data)
		return opCode, pkt, err
	case OpTodData:
		pkt, err := parseTodDataPacket(data)
		return opCode, pkt, err
	default:
		return opCode, nil, nil
	}
}

func parseDMXPacket(data []byte) (*DMXPacket, error) {
	if len(data) < 18 {
		return nil, ErrPacketTooShort
	}

	pkt := &DMXPacket{
		ProtocolVersion: binary.BigEndian.Uint16(data[10:12]),
		Sequence:        data[12],
		Physical:        data[13],
		Universe:        Universe(binary.LittleEndian.Uint16(data[14:16])),
		Length:          binary.BigEndian.Uint16(data[16:18]),
	}

	dataLen := int(pkt.Length)
	if dataLen > 512 {
		dataLen = 512
	}
	if len(data) >= 18+dataLen {
		copy(pkt.Data[:], data[18:18+dataLen])
	}

	return pkt, nil
}

func parsePollPacket(data []byte) (*PollPacket, error) {
	if len(data) < 14 {
		return nil, ErrPacketTooShort
	}

	return &PollPacket{
		ProtocolVersion: binary.BigEndian.Uint16(data[10:12]),
		Flags:           data[12],
		DiagPriority:    data[13],
	}, nil
}

func parsePollReplyPacket(data []byte) (*PollReplyPacket, error) {
	if len(data) < 214 {
		return nil, ErrPacketTooShort
	}

	pkt := &PollReplyPacket{
		Port:        binary.LittleEndian.Uint16(data[14:16]),
		VersionInfo: binary.BigEndian.Uint16(data[16:18]),
		NetSwitch:   data[18],
		SubSwitch:   data[19],
		OemHi:       data[20],
		Oem:         data[21],
		UbeaVersion: data[22],
		Status1:     data[23],
		EstaMan:     binary.LittleEndian.Uint16(data[24:26]),
		NumPortsHi:  data[172],
		NumPortsLo:  data[173],
		Style:       data[200],
		BindIndex:   data[212],
		Status2:     data[213],
	}

	copy(pkt.IPAddress[:], data[10:14])
	copy(pkt.ShortName[:], data[26:44])
	copy(pkt.LongName[:], data[44:108])
	copy(pkt.NodeReport[:], data[108:172])
	copy(pkt.PortTypes[:], data[174:178])
	copy(pkt.GoodInput[:], data[178:182])
	copy(pkt.GoodOutput[:], data[182:186])
	copy(pkt.SwIn[:], data[186:190])
	copy(pkt.SwOut[:], data[190:194])
	copy(pkt.MAC[:], data[201:207])
	copy(pkt.BindIP[:], data[207:211])

	return pkt, nil
}

func BuildDMXPacket(universe Universe, sequence uint8, data []byte) []byte {
	dataLen := len(data)
	if dataLen > 512 {
		dataLen = 512
	}
	if dataLen%2 != 0 {
		dataLen++
	}

	buf := make([]byte, 18+dataLen)
	copy(buf[0:8], ID[:])
	binary.LittleEndian.PutUint16(buf[8:10], OpDmx)
	binary.BigEndian.PutUint16(buf[10:12], ProtocolVersion)
	buf[12] = sequence
	buf[13] = 0
	binary.LittleEndian.PutUint16(buf[14:16], uint16(universe))
	binary.BigEndian.PutUint16(buf[16:18], uint16(dataLen))
	copy(buf[18:], data[:dataLen])

	return buf
}

func BuildPollPacket() []byte {
	buf := make([]byte, 14)
	copy(buf[0:8], ID[:])
	binary.LittleEndian.PutUint16(buf[8:10], OpPoll)
	binary.BigEndian.PutUint16(buf[10:12], ProtocolVersion)
	buf[12] = 0x00
	buf[13] = 0x00
	return buf
}

func parseTodDataPacket(data []byte) (*TodDataPacket, error) {
	if len(data) < 28 {
		return nil, ErrPacketTooShort
	}

	pkt := &TodDataPacket{
		RdmVer:     data[10],
		Port:       data[11],
		BindIndex:  data[20],
		Net:        data[21],
		Command:    data[22],
		Universe:   NewUniverse(data[21], data[23]>>4, data[23]&0x0F),
		UidTotal:   binary.BigEndian.Uint16(data[24:26]),
		BlockCount: data[26],
		UidCount:   data[27],
	}

	uidCount := int(pkt.UidCount)
	if uidCount > 200 {
		uidCount = 200
	}

	expectedLen := 28 + uidCount*6
	if len(data) < expectedLen {
		uidCount = (len(data) - 28) / 6
	}

	pkt.UIDs = make([]RDMUID, uidCount)
	for i := 0; i < uidCount; i++ {
		copy(pkt.UIDs[i][:], data[28+i*6:28+i*6+6])
	}

	return pkt, nil
}

func BuildTodRequestPacket(net, subnet, universe uint8) []byte {
	buf := make([]byte, 25)
	copy(buf[0:8], ID[:])
	binary.LittleEndian.PutUint16(buf[8:10], OpTodRequest)
	binary.BigEndian.PutUint16(buf[10:12], ProtocolVersion)
	buf[20] = net
	buf[21] = TodCommandFull
	buf[22] = 1
	buf[23] = subnet<<4 | (universe & 0x0F)
	return buf
}

func BuildPollReplyPacket(ip [4]byte, mac [6]byte, shortName, longName string, universes []Universe, isInput bool) []byte {
	buf := make([]byte, 240)
	copy(buf[0:8], ID[:])
	binary.LittleEndian.PutUint16(buf[8:10], OpPollReply)
	copy(buf[10:14], ip[:])
	binary.LittleEndian.PutUint16(buf[14:16], Port)
	binary.BigEndian.PutUint16(buf[16:18], ProtocolVersion)

	if len(universes) > 0 {
		buf[18] = universes[0].Net()
		buf[19] = universes[0].SubNet()
	}

	copy(buf[26:44], shortName)
	copy(buf[44:108], longName)

	numPorts := len(universes)
	if numPorts > 4 {
		numPorts = 4
	}
	buf[173] = byte(numPorts)

	for i := 0; i < numPorts; i++ {
		if isInput {
			buf[174+i] = PortTypeInput
			buf[178+i] = GoodInputDataReceived
			buf[186+i] = universes[i].Universe()
		} else {
			buf[174+i] = PortTypeOutput
			buf[182+i] = GoodOutputDataTransmitted
			buf[190+i] = universes[i].Universe()
		}
	}

	copy(buf[201:207], mac[:])
	copy(buf[207:211], ip[:])
	buf[211] = 1
	buf[212] = 0x08

	return buf
}
