/*
  Copyright 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/



package inet

import "sync"
//import "github.com/google/gopacket/layers"
//import "github.com/google/gopacket"
import "net"

type Host4 struct{
	Addr, Net, BC, GW IPv4
}
func (h *Host4) Input4(ip IPv4) bool {
	return h.Addr==ip || h.BC==ip || ip==0xFFFFFFFF
}

type IPv6He struct{
	/* Addresses, {Uni,Multi}cast(s) */
	Unicast, Solicited IPv6
	
	/* Network Mask */
	PrefixMask IPv6
}

type Host6 struct{
	MTX sync.RWMutex
	Addrs map[IPv6]IPv6He
}
func (h *Host6) Init6() {
	h.Addrs = make(map[IPv6]IPv6He)
}

// If nr==true then the address is not a Multicast.
// Else If my==false then the packet is to be dropped.
// Otherwise the packet is for us.
func InputMC6(ip IPv6) (my bool,nr bool) {
	u := uint16(ip[0]>>48)
	/* START IF ip.bytes[0] == 0xff */
	if (u&0xff00) == 0xff00 {
		/* START SWITCH( ip.bytes[1] & 0xf ) */
		switch u&0xf{
		/*
		 * RFC 4291 2.7
		 * 
		 * Nodes must not originate a packet to a multicast address whose scop
		 * field contains the reserved value 0; if such a packet is received, it
		 * must be silently dropped.
		 */
		// (Case 0)
		/*
		 * RFC 4291 - Errata ID: 3480
		 *
		 * Section 2.7 says: 
		 *  Interface-Local scope spans only a single interface on a node
		 *  and is useful only for loopback transmission of multicast.
		 * 
		 * It should say:
		 *  Interface-Local scope spans only a single interface on a node 
		 *  and is useful only for loopback transmission of multicast.
		 *  Packets with interface-local scope received from another node 
		 *  must be discarded.
		 *
		 * It should be explicitly stated that interface-local scoped multicast packets
		 * received from the link must be discarded.
		 * The BSD implementation currently does this, but not Linux.
		 * http://www.ietf.org/mail-archive/web/ipv6/current/msg17154.html 
		 */
		// (Case 1)
		case 0,1: return false,false
		default: return true,false
		}
		/* END SWITCH( ip.bytes[1] & 0xf ) */
	}
	/* END IF ip.bytes[0] == 0xff */
	return false,true
}
func (h *Host6) Input6(ip IPv6) bool {
	
	/* Check Multicastisms */
	
	my,nr := InputMC6(ip)
	if nr{ return my }
	
	h.MTX.RLock(); defer h.MTX.RUnlock()
	
	_,my = h.Addrs[ip]
	
	return my
}
func (h *Host6) BulkInputUC6(ips []IPv6,oks []bool) {
	h.MTX.RLock(); defer h.MTX.RUnlock()
	for i,ip := range ips {
		_,oks[i] = h.Addrs[ip]
	}
}
func (h *Host6) BulkInput6(ips []IPv6,oks []bool) {
	h.BulkInputUC6(ips,oks)
	for i,ip := range ips {
		my,nr := InputMC6(ip)
		oks[i] = (oks[i]&&nr)||my
	}
}

type Host struct{
	Host4
	Host6
}
func (h *Host) Input(ip net.IP) bool {
	if i4 := ip.To4(); len(i4)==4 {
		var i4s IPv4
		i4s.FromIP(ip)
		return h.Input4(i4s)
	}
	var i6s IPv6
	i6s.FromIP(ip)
	return h.Input6(i6s)
}






