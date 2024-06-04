package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type direction uint8

const (
	directionIngress direction = iota
	directionEgress
)

func (d direction) String() string {
	switch d {
	case directionIngress:
		return "ingress"
	case directionEgress:
		return "egress"
	default:
		return "unknown"
	}
}

type key struct {
	macaddr   net.HardwareAddr
	ip        netip.Addr
	ifindex   uint32
	direction direction
}

func (k *key) size() int {
	// IP        (4)
	// Ifindex   (4)
	// Mac       (6)
	// Direction (1)
	// Padding   (1)
	return 16
}

func (k key) String() string {
	return fmt.Sprintf("ip:%s macaddr:%s ifindex:%d direction:%s",
		k.ip, k.macaddr, k.ifindex, k.direction)
}

func (k *key) UnmarshalBinary(data []byte) error {
	if len(data) != k.size() {
		return fmt.Errorf("failed to unmarshal, got size %d expected %d",
			len(data), k.size())
	}

	var ok bool
	k.ip, ok = netip.AddrFromSlice(data[0:4])
	if !ok {
		return fmt.Errorf("failed to get unmarshal key ip")
	}

	k.ifindex = binary.NativeEndian.Uint32(data[4:8])

	k.macaddr = make([]byte, 6)
	for i := 0; i < 6; i++ {
		k.macaddr[i] = data[8+i]
	}

	k.direction = direction(data[14])

	return nil
}

type value struct {
	packets  uint64
	bytes    uint64
	lastSeen time.Time
}

func (v *value) size() int {
	// Packets    8
	// Bytes      8
	// Timestamp  8
	return 24
}

func (v *value) UnmarshalBinary(data []byte) error {
	if len(data) != v.size() {
		return fmt.Errorf("failed to unmarshal value size:%d", len(data))
	}
	v.packets = binary.NativeEndian.Uint64(data[0:8])
	v.bytes = binary.NativeEndian.Uint64(data[8:16])

	ts := int64(binary.NativeEndian.Uint64(data[16:]))
	v.lastSeen = time.Unix(0, int64(ts))

	return nil
}

func (v value) String() string {
	return fmt.Sprintf("pkts:%d bytes:%d last_seen:%s",
		v.packets, v.bytes, time.Since(v.lastSeen))
}
