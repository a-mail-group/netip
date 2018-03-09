/*
  Copyright 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/



package inet

import "net"

type IPv4 uint32

func (i *IPv4) FromIP(raw net.IP) {
	j := uint32(raw[0])<<24
	j |= uint32(raw[1])<<16
	j |= uint32(raw[2])<<8
	j |= uint32(raw[3])
	*i = IPv4(j)
}

func (i IPv4) ToIP(buf net.IP) net.IP {
	return append(buf[:0],
		byte(i>>24),
		byte(i>>16),
		byte(i>> 8),
		byte(i    ))
}

type IPv6 [2]uint64

func (i *IPv6) FromIP(raw net.IP) {
	j := uint64(raw[0])<<56
	j |= uint64(raw[1])<<48
	j |= uint64(raw[2])<<40
	j |= uint64(raw[3])<<32
	j |= uint64(raw[4])<<24
	j |= uint64(raw[5])<<16
	j |= uint64(raw[6])<< 8
	j |= uint64(raw[7])
	i[0] = j
	j  = uint64(raw[ 8])<<56
	j |= uint64(raw[ 9])<<48
	j |= uint64(raw[10])<<40
	j |= uint64(raw[11])<<32
	j |= uint64(raw[12])<<24
	j |= uint64(raw[13])<<16
	j |= uint64(raw[14])<< 8
	j |= uint64(raw[15])
	i[1] = j
}
func (i *IPv6) ToIP(buf net.IP) net.IP {
	return append(buf[:0],
		byte(i[0]>>56),
		byte(i[0]>>48),
		byte(i[0]>>40),
		byte(i[0]>>32),
		byte(i[0]>>24),
		byte(i[0]>>16),
		byte(i[0]>> 8),
		byte(i[0]    ),
		byte(i[1]>>56),
		byte(i[1]>>48),
		byte(i[1]>>40),
		byte(i[1]>>32),
		byte(i[1]>>24),
		byte(i[1]>>16),
		byte(i[1]>> 8),
		byte(i[1]    ))
}



