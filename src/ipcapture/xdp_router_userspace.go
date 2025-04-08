package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	ETH_ALEN = 6
)

// Structs for routing
type LpmTrieKey struct {
	Prefixlen uint32
	IP        uint32
}

type RouteEntry struct {
	OutIfindex int32
	NextHopMac [ETH_ALEN]byte
}

// Struct to hold eBPF objects
type xdpRouterObjects struct {
	XdpRouter   *ebpf.Program
	RoutingTable *ebpf.Map
}

// Convert IP string to uint32
func ipToUint32(ip string) (uint32, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, errors.New("invalid IP address")
	}
	return binary.BigEndian.Uint32(parsedIP.To4()), nil
}

// Add route entry to the eBPF routing table
func addRouteEntry(routingTable *ebpf.Map, prefixlen uint32, ip string, outIfindex int32, nextHopMac net.HardwareAddr) error {
	ipUint, err := ipToUint32(ip)
	if err != nil {
		return err
	}

	key := LpmTrieKey{Prefixlen: prefixlen, IP: ipUint}
	nextHop := RouteEntry{OutIfindex: outIfindex}
	copy(nextHop.NextHopMac[:], nextHopMac)

	return routingTable.Put(&key, &nextHop)
}

// Display the routing table
func displayRoutingTable(routingTable *ebpf.Map) {
	fmt.Println("\nRouting Table:")
	fmt.Printf("%-15s %-5s %-17s\n", "Destination", "Prefix", "Next Hop MAC")

	var key LpmTrieKey
	var entry RouteEntry
	it := routingTable.Iterate()

	for it.Next(&key, &entry) {
		ip := net.IPv4(byte(key.IP>>24), byte(key.IP>>16), byte(key.IP>>8), byte(key.IP))
		fmt.Printf("%-15s %-5d %02x:%02x:%02x:%02x:%02x:%02x\n",
			   ip.String(), key.Prefixlen,
			   entry.NextHopMac[0], entry.NextHopMac[1], entry.NextHopMac[2],
	     entry.NextHopMac[3], entry.NextHopMac[4], entry.NextHopMac[5])
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <ifname>\n", os.Args[0])
		os.Exit(1)
	}

	ifname := os.Args[1]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		fmt.Printf("Invalid interface name %s\n", ifname)
		os.Exit(1)
	}

	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("xdp_router.bpf.o")
	if err != nil {
		fmt.Println("Failed to load XDP program:", err)
		os.Exit(1)
	}

	// Create eBPF objects
	var objs xdpRouterObjects
	err = spec.LoadAndAssign(&objs, nil) // Fixed function signature
	if err != nil {
		fmt.Println("Failed to load and assign eBPF objects:", err)
		os.Exit(1)
	}

	// Attach XDP program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRouter,
		Interface: iface.Index,
	})
	if err != nil {
		fmt.Println("Failed to attach XDP program:", err)
		os.Exit(1)
	}

	defer xdpLink.Close()
	fmt.Printf("Router is running on interface %s\n", ifname)

	// Handle signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Fetch the routing table from eBPF
	routingTable := objs.RoutingTable
	for {
		select {
			case <-signalChan:
				fmt.Println("Exiting...")
				return
			default:
				displayRoutingTable(routingTable)
				time.Sleep(10 * time.Second)
		}
	}
}
