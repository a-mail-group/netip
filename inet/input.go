/*
  Copyright 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/



package inet

import "sync"
import "github.com/google/gopacket/layers"
import "github.com/google/gopacket"
import "net"
import "encoding/binary"

type IPPacket struct {
	layers.BaseLayer
	// Hop-By-Hop option
	HopByHop []byte
	Flow   gopacket.Flow
	SrcIP, DstIP net.IP
	
	/* Space for the local copies of the IP-Addresses. */
	ipspace [32]byte
	
	FragIdent  uint32
	FragOff    uint16
	
	Protocol layers.IPProtocol
	TOS    uint8
	TTL    uint8
	
	Is6      bool
	FragMore bool
}
func (pkt *IPPacket) LocalizeIP() {
	ip := append(pkt.ipspace[:0],pkt.SrcIP...)
	ip  = append(ip,pkt.DstIP...)
	pkt.SrcIP = ip[:len(pkt.SrcIP) ]
	pkt.DstIP = ip[ len(pkt.SrcIP):]
}
func (pkt *IPPacket) Release() {
	// Un-assign possible pointers to external arrays.
	pkt.BaseLayer = layers.BaseLayer{}
	pkt.SrcIP = nil
	pkt.DstIP = nil
	
	// Free The block.
	ipPacketPool.Put(pkt)
}

var ipPacketPool = sync.Pool{ New:func() interface{} { return new(IPPacket) } }

var ipv4Pool = sync.Pool{ New:func() interface{} { return new(layers.IPv4) } }
var ipv6Pool = sync.Pool{ New:func() interface{} { return new(layers.IPv6) } }

func DecodeIPPacket(data []byte,lt gopacket.LayerType) (*IPPacket,error) {
	var pkt *IPPacket
	switch lt {
	case layers.LayerTypeIPv4:{
			iplayer := ipv4Pool.Get().(*layers.IPv4)
			err := iplayer.DecodeFromBytes(data,gopacket.NilDecodeFeedback)
			if err!=nil { return nil,err }
			pkt = ipPacketPool.Get().(*IPPacket)
			//*pkt = IPPacket{}
			pkt.BaseLayer = iplayer.BaseLayer
			pkt.Protocol  = iplayer.Protocol
			pkt.Flow      = iplayer.NetworkFlow()
			pkt.SrcIP     = iplayer.SrcIP
			pkt.DstIP     = iplayer.DstIP
			pkt.TOS       = iplayer.TOS
			pkt.TTL       = iplayer.TTL
			pkt.Is6       = false
			pkt.FragIdent = uint32(iplayer.Id)
			pkt.FragOff   = iplayer.FragOffset
			pkt.FragMore  = (iplayer.Flags&1)!=0
			if pkt.FragOff!=0 || pkt.FragMore { return pkt,nil }
			ipv4Pool.Put(iplayer)
		}
	case layers.LayerTypeIPv6:{
			iplayer := ipv6Pool.Get().(*layers.IPv6)
			err := iplayer.DecodeFromBytes(data,gopacket.NilDecodeFeedback)
			if err!=nil { return nil,err }
			pkt = ipPacketPool.Get().(*IPPacket)
			//*pkt = IPPacket{}
			pkt.BaseLayer = iplayer.BaseLayer
			pkt.Protocol  = iplayer.NextHeader
			pkt.Flow      = iplayer.NetworkFlow()
			pkt.SrcIP     = iplayer.SrcIP
			pkt.DstIP     = iplayer.DstIP
			pkt.TOS       = iplayer.TrafficClass /* IPv4's TOS and IPv6's Traffic-Class contain the same thing: DSCP+EC */
			pkt.TTL       = iplayer.HopLimit
			pkt.Is6       = true
			pkt.FragIdent = 0
			pkt.FragOff   = 0
			pkt.FragMore  = false
			ipv6Pool.Put(iplayer)
		}
	default: return nil,nil
	}
	var es *layers.IPv6ExtensionSkipper
	for {
		switch pkt.Protocol {
		case layers.IPProtocolIPv6HopByHop,
		     layers.IPProtocolIPv6Routing,
		     layers.IPProtocolIPv6Destination:
			if es == nil { es = new(layers.IPv6ExtensionSkipper) }
			err := es.DecodeFromBytes(es.Payload,gopacket.NilDecodeFeedback)
			if err!=nil { return nil,err }
			if pkt.Protocol==layers.IPProtocolIPv6HopByHop { pkt.HopByHop = es.BaseLayer.Contents }
			pkt.Payload   = es.Payload
			pkt.Protocol  = es.NextHeader
			continue
		case layers.IPProtocolIPv6Fragment:
			{
				pl := pkt.Payload
				pkt.Payload = pl[8:]
				pkt.FragOff = binary.BigEndian.Uint16(pl[2:4]) >> 3
				pkt.FragMore = (pl[3]&1)!=0
				pkt.FragIdent = binary.BigEndian.Uint32(pl[4:8])
				if pkt.FragOff!=0 || pkt.FragMore { return pkt,nil }
			}
			continue
		}
		break
	}
	return pkt,nil
}


