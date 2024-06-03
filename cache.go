package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
)

type cache struct {
	mu        sync.Mutex
	linkNames map[int]netlink.Link
	leases    map[string]string
}

func newCache() *cache {
	return &cache{
		linkNames: map[int]netlink.Link{},
		leases:    map[string]string{},
	}
}

func (c *cache) setLeaseName(macaddr, name string) {
	macaddr = strings.ToLower(macaddr)
	oldName, ok := c.leaseName(macaddr)
	if ok {
		if oldName == name {
			return
		}

		fmt.Printf("Updating entry macaddr:%q name:%q->%q\n", macaddr, oldName, name)
	} else {
		fmt.Printf("Adding entry lease macaddr:%q name:%q\n", macaddr, name)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.leases[macaddr] = name
}

func (c *cache) leaseName(macaddr string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.leases[macaddr]
	return s, ok
}

func (c *cache) linkName(ifindex uint32) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	index := int(ifindex)
	link, ok := c.linkNames[index]
	if ok {
		return link.Attrs().Name
	}

	link, err := netlink.LinkByIndex(index)
	if err != nil {
		fmt.Printf("Failed to get interface name for ifindex:%d\n", index)
		return strconv.Itoa(index)
	}

	linkName := link.Attrs().Name
	fmt.Printf("Adding link %q to cache\n", linkName)
	c.linkNames[index] = link
	return linkName
}
