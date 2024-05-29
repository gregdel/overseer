package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

type key struct {
	macaddr net.HardwareAddr
	ip      netip.Addr
}

func (k *key) expectedSize() int {
	// IP  (4)
	// Mac (6)
	// Padding (2)
	return 12
}

func (k key) String() string {
	return fmt.Sprintf("%s [%s]", k.ip, k.macaddr)
}

func (k *key) UnmarshalBinary(data []byte) error {
	if len(data) != k.expectedSize() {
		return fmt.Errorf("failed to unmarshal, got size %d expected %d",
			len(data), k.expectedSize())
	}

	var ok bool
	k.ip, ok = netip.AddrFromSlice(data[0:4])
	if !ok {
		return fmt.Errorf("failed to get unmarshal key ip")
	}

	k.macaddr = make([]byte, 6)
	for i := 0; i < 6; i++ {
		k.macaddr[i] = data[4+i]
	}

	return nil
}

type value struct {
	packets uint64
	bytes   uint64
}

func (v *value) UnmarshalBinary(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("failed to unmarshal value size:%d", len(data))
	}
	v.packets = binary.NativeEndian.Uint64(data[0:8])
	v.bytes = binary.NativeEndian.Uint64(data[8:])
	return nil
}
