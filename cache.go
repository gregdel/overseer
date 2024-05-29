package main

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/vishvananda/netlink"
)

type cache struct {
	mu        sync.Mutex
	linkNames map[int]netlink.Link
}

func newCache() *cache {
	return &cache{
		linkNames: map[int]netlink.Link{},
	}
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
