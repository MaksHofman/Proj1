package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"      // ← NOWY
)


/* --- parametry PWOSPF HELLO --- */
const (
	HelloInt        = 5 * time.Second          // co ile wysyłamy HELLO
	NeighborTimeout = 3 * HelloInt             // brak HELLO → usuwamy sąsiada
	PWOSPFVersion   = 2                        // wersja protokołu
	AllSPFAddr      = "224.0.0.5:261"          // RFC → multicast + port OSPF
)

/* --- struktury pakietu (okrojone do minimum potrzebnego w demo) --- */
type helloPkt struct {
	Version    uint8  // =2
	AreaID     uint32 // zgodny z routerem
	NetworkMsk uint32 // maska interfejsu
	HelloInt   uint16 // sekundy
	_          [2]byte
	Checksum   uint16 // proste RFC‑style, tu ignorujemy
}

func (p *helloPkt) Marshal() []byte {
	buf := make([]byte, 16)
	buf[0] = p.Version
	binary.BigEndian.PutUint32(buf[1:], p.AreaID)
	binary.BigEndian.PutUint32(buf[5:], p.NetworkMsk)
	binary.BigEndian.PutUint16(buf[9:], p.HelloInt)
	// buf[11:13] = 0 // padding
	// buf[13:15] = p.Checksum (tu pomijamy)
	return buf
}

func parseHello(b []byte) (*helloPkt, bool) {
	if len(b) < 16 || b[0] != PWOSPFVersion {
		return nil, false
	}
	p := &helloPkt{
		Version:    b[0],
		AreaID:     binary.BigEndian.Uint32(b[1:]),
		NetworkMsk: binary.BigEndian.Uint32(b[5:]),
		HelloInt:   binary.BigEndian.Uint16(b[9:]),
	}
	return p, true
}

/* --- baza sąsiadów --- */
type neighbor struct {
	ip        net.IP
	lastHeard time.Time
	mask      uint32
}

var neighTable = make(map[string]*neighbor)

/* --- gorutyna 1: wysyłanie HELLO --- */
func helloSender(iface string, areaID uint32, netmask uint32) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("HELLO: no such interface:", iface)
		return
	}

	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.5"), Port: 261}

	/*  1. tworzymy „goły” datagram UDP (ListenPacket)             */
	conn, err := net.ListenPacket("udp4", "") // 0.0.0.0:any
	if err != nil {
		fmt.Println("HELLO: ListenPacket failed:", err)
		return
	}
	raw := ipv4.NewPacketConn(conn)
	defer raw.Close()

	/*  2. wymuszamy wysyłanie multicastu przez wybrany interfejs  */
	if err := raw.SetMulticastInterface(ifaceObj); err != nil {
		fmt.Println("HELLO: SetMulticastInterface:", err)
		return
	}
	raw.SetMulticastTTL(1)        // lokalny segment – zgodnie z RFC OSPF

	pkt := &helloPkt{
		Version:    PWOSPFVersion,
		AreaID:     areaID,
		NetworkMsk: netmask,
		HelloInt:   uint16(HelloInt.Seconds()),
	}

	/*  3. pętla wysyłająca co HelloInt sekund                    */
	for {
		_, err := raw.WriteTo(pkt.Marshal(), nil, group)
		if err != nil {
			fmt.Println("HELLO: send error:", err)
		}
		time.Sleep(HelloInt)
	}
}


/* --- gorutyna 2: odbiór HELLO --- */
func helloReceiver(iface string, areaID uint32, netmask uint32) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("HELLO RX: no such interface:", iface)
		return
	}

	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.5"), Port: 261}

	// Nasłuch na UDP port 261
	conn, err := net.ListenPacket("udp4", ":261")
	if err != nil {
		fmt.Println("HELLO RX: ListenPacket error:", err)
		return
	}
	pc := ipv4.NewPacketConn(conn)
	defer pc.Close()

	// Dołączenie do grupy multicast na danym interfejsie
	if err := pc.JoinGroup(ifaceObj, group); err != nil {
		fmt.Println("HELLO RX: JoinGroup error:", err)
		return
	}

	buf := make([]byte, 1500)
	for {
		n, _, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}

		pkt, ok := parseHello(buf[:n])
		if !ok {
			continue
		}

		// Teraz można bezpiecznie odwołać się do pól pkt
		if pkt.AreaID != areaID ||
			pkt.NetworkMsk != netmask ||
			pkt.HelloInt != uint16(HelloInt.Seconds()) {
				continue
			}

			ip := src.String()
			if nb, ok := neighTable[ip]; ok {
				nb.lastHeard = time.Now()
			} else {
				neighTable[ip] = &neighbor{
					ip:        net.ParseIP(ip),
					lastHeard: time.Now(),
					mask:      pkt.NetworkMsk,
				}
				fmt.Println("=== HELLO: nowy sąsiad →", ip)
			}
	}
}

/* --- gorutyna 3: kasowanie martwych sąsiadów --- */
func neighborGC() {
	for {
		now := time.Now()
		for ip, nb := range neighTable {
			if now.Sub(nb.lastHeard) > NeighborTimeout {
				fmt.Println("=== HELLO: usuwam nieaktywnego →", ip)
				delete(neighTable, ip)
			}
		}
		time.Sleep(HelloInt)
	}
}

/* --- wywołanie startowe dla main.go --- */
func startHelloSubsystem(iface string, areaID uint32, netmask uint32) {
	go helloSender(iface, areaID, netmask)
	go helloReceiver(iface, areaID, netmask)
	go neighborGC()
}
