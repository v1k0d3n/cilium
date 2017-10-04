// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"sort"
)

const (
	ipv4BitLen = 8 * net.IPv4len
	ipv6BitLen = 8 * net.IPv6len
)

var (
	v4Asv6            = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}
	ipv4LeadingZeroes = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
)

// NetsByMask is used to sort a list of IP networks by the size of their masks.
// Implements sort.Interface.
type NetsByMask []*net.IPNet

func (s NetsByMask) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s NetsByMask) Less(i, j int) bool {
	iPrefixSize, _ := s[i].Mask.Size()
	jPrefixSize, _ := s[j].Mask.Size()
	if iPrefixSize == jPrefixSize {
		if bytes.Compare(s[i].IP, s[j].IP) < 0 {
			return true
		}
		return false
	}
	return iPrefixSize < jPrefixSize
}

func (s NetsByMask) Len() int {
	return len(s)
}

// Assert that NetsByMask implements sort.Interface.
var _ sort.Interface = NetsByMask{}

// NetSorter (TODO: rename)
type NetsByMeta []*netWithRange

func (s NetsByMeta) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s NetsByMeta) Less(i, j int) bool {
	// Sort by first IP, then by size of network bits, then by host bits.

	iPrefixSize, _ := s[i].Network.Mask.Size()
	jPrefixSize, _ := s[j].Network.Mask.Size()

	// Sort first by first IP
	firstComparison := bytes.Compare(*s[i].First, *s[j].First)
	if firstComparison < 0 {
		return true
	} else if firstComparison > 0 {
		return false
	}

	// If first addresses are equal, check by size of network bits.
	iNetSizeBits := iPrefixSize - 1
	jNetSizeBits := jPrefixSize - 1
	if iNetSizeBits < jNetSizeBits {
		return true
	} else if iNetSizeBits > jNetSizeBits {
		return false
	}

	// If size of network bits equal, check by host bits.
	iNetBig := big.NewInt(0).SetBytes(s[i].Network.IP)
	iNetFirstBig := big.NewInt(0).SetBytes(*s[i].First)
	jNetBig := big.NewInt(0).SetBytes(s[j].Network.IP)
	jNetFirstBig := big.NewInt(0).SetBytes(*s[j].First)

	iNetHostBig := big.NewInt(0)
	iNetHostBig = iNetHostBig.Sub(iNetBig, iNetFirstBig)

	jNetHostBig := big.NewInt(0)
	jNetHostBig = jNetHostBig.Sub(jNetBig, jNetFirstBig)

	if iNetHostBig.Cmp(jNetHostBig) < 0 {
		return false
	}

	return true

	// If size of network bits is equal, then check host bits.

}

func (s NetsByMeta) Len() int {
	return len(s)
}

// RemoveCIDRs removes the specified CIDRs from another set of CIDRs. If a CIDR to remove is not
// contained within the CIDR, the CIDR to remove is ignored. A slice of CIDRs is
// returned which contains the set of CIDRs provided minus the set of CIDRs which
// were removed. Both input slices may be modified by calling this function.
func RemoveCIDRs(allowCIDRs, removeCIDRs []*net.IPNet) ([]*net.IPNet, error) {

	// Ensure that we iterate through the provided CIDRs in order of largest
	// subnet first.
	sort.Sort(NetsByMask(removeCIDRs))

PreLoop:
	// Remove CIDRs which are contained within CIDRs that we want to remove;
	// such CIDRs are redundant.
	for j, removeCIDR := range removeCIDRs {
		for i, removeCIDR2 := range removeCIDRs {
			if i == j {
				continue
			}
			if removeCIDR.Contains(removeCIDR2.IP) {
				removeCIDRs = append(removeCIDRs[:i], removeCIDRs[i+1:]...)
				// Re-trigger loop since we have modified the slice we are iterating over.
				goto PreLoop
			}
		}
	}

	for _, remove := range removeCIDRs {
	Loop:
		for i, allowCIDR := range allowCIDRs {

			// Don't allow comparison of different address spaces.
			if allowCIDR.IP.To4() != nil && remove.IP.To4() == nil ||
				allowCIDR.IP.To4() == nil && remove.IP.To4() != nil {
				return nil, fmt.Errorf("cannot mix IP addresses of different IP protocol versions")
			}

			// Only remove CIDR if it is contained in the subnet we are allowing.
			if allowCIDR.Contains(remove.IP.Mask(remove.Mask)) {
				nets, err := removeCIDR(allowCIDR, remove)
				if err != nil {
					return nil, err
				}

				// Remove CIDR that we have just processed and append new CIDRs
				// that we computed from removing the CIDR to remove.
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				allowCIDRs = append(allowCIDRs, nets...)
				goto Loop
			} else if remove.Contains(allowCIDR.IP.Mask(allowCIDR.Mask)) {
				// If a CIDR that we want to remove contains a CIDR in the list
				// that is allowed, then we can just remove the CIDR to allow.
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				goto Loop
			}
		}
	}

	return allowCIDRs, nil
}

func getNetworkPrefix(ipNet *net.IPNet) *net.IP {
	var mask net.IP

	if ipNet.IP.To4() == nil {
		mask = make(net.IP, net.IPv6len)
		for i := 0; i < len(ipNet.Mask); i++ {
			mask[net.IPv6len-i-1] = ipNet.IP[net.IPv6len-i-1] & ^ipNet.Mask[i]
		}
	} else {
		mask = make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			mask[net.IPv4len-i-1] = ipNet.IP[net.IPv6len-i-1] & ^ipNet.Mask[i]
		}
	}

	return &mask
}

func removeCIDR(allowCIDR, removeCIDR *net.IPNet) ([]*net.IPNet, error) {
	var allows []*net.IPNet
	var allowIsIpv4, removeIsIpv4 bool
	var allowBitLen int

	if allowCIDR.IP.To4() != nil {
		allowIsIpv4 = true
		allowBitLen = ipv4BitLen
	} else {
		allowBitLen = ipv6BitLen
	}

	if removeCIDR.IP.To4() != nil {
		removeIsIpv4 = true
	}

	if removeIsIpv4 != allowIsIpv4 {
		return nil, fmt.Errorf("cannot mix IP addresses of different IP protocol versions")
	}

	// Get size of each CIDR mask.
	allowSize, _ := allowCIDR.Mask.Size()
	removeSize, _ := removeCIDR.Mask.Size()

	if allowSize >= removeSize {
		return nil, fmt.Errorf("allow CIDR prefix must be a superset of " +
			"remove CIDR prefix")
	}

	allowFirstIPMasked := allowCIDR.IP.Mask(allowCIDR.Mask)
	removeFirstIPMasked := removeCIDR.IP.Mask(removeCIDR.Mask)

	// Convert to IPv4 in IPv6 addresses if needed.
	if allowIsIpv4 {
		allowFirstIPMasked = append(v4Asv6, allowFirstIPMasked...)
	}

	if removeIsIpv4 {
		removeFirstIPMasked = append(v4Asv6, removeFirstIPMasked...)
	}

	allowFirstIP := &allowFirstIPMasked
	removeFirstIP := &removeFirstIPMasked

	// Create CIDR prefixes with mask size of Y+1, Y+2 ... X where Y is the mask
	// length of the CIDR prefix B from which we are excluding a CIDR prefix A
	// with mask length X.
	for i := (allowBitLen - allowSize - 1); i >= (allowBitLen - removeSize); i-- {
		// The mask for each CIDR prefix is simply the ith bit flipped, and then
		// zero'ing out all subsequent bits (the host identifier part of the
		// prefix).
		newMaskSize := allowBitLen - i
		newIP := (*net.IP)(flipNthBit((*[]byte)(removeFirstIP), uint(i)))
		for k := range *allowFirstIP {
			(*newIP)[k] = (*allowFirstIP)[k] | (*newIP)[k]
		}

		newMask := net.CIDRMask(newMaskSize, allowBitLen)
		newIPMasked := newIP.Mask(newMask)

		newIPNet := net.IPNet{IP: newIPMasked, Mask: newMask}
		allows = append(allows, &newIPNet)
	}

	return allows, nil
}

func getByteIndexOfBit(bit uint) uint {
	return net.IPv6len - (bit / 8) - 1
}

func getNthBit(ip *net.IP, bitNum uint) uint8 {
	byteNum := getByteIndexOfBit(bitNum)
	bits := (*ip)[byteNum]
	b := uint8(bits)
	return b >> (bitNum % 8) & 1
}

func flipNthBit(ip *[]byte, bitNum uint) *[]byte {
	ipCopy := make([]byte, len(*ip))
	copy(ipCopy, *ip)
	byteNum := getByteIndexOfBit(bitNum)
	ipCopy[byteNum] = ipCopy[byteNum] ^ 1<<(bitNum%8)

	return &ipCopy
}

func MergeCIDRS(cidrs []*net.IPNet) []*net.IPNet {
	return nil
}

func ipNetToRange(ipNet net.IPNet) netWithRange {
	firstIP := make(net.IP, len(ipNet.IP))
	copy(firstIP, ipNet.IP)
	firstIP = firstIP.Mask(ipNet.Mask)
	if firstIP.To4() != nil {
		firstIP = append(v4Asv6, firstIP...)
	}
	lastIP := make(net.IP, len(ipNet.IP))
	copy(lastIP, ipNet.IP)
	lastIPMask := make(net.IPMask, len(ipNet.Mask))
	copy(lastIPMask, ipNet.Mask)
	for i := range lastIPMask {
		lastIPMask[len(lastIPMask)-i-1] = ^lastIPMask[len(lastIPMask)-i-1]
		lastIP[net.IPv6len-i-1] = lastIP[net.IPv6len-i-1] | lastIPMask[len(lastIPMask)-i-1]
	}

	if len(firstIP) == net.IPv4len {
		firstIP = append(v4Asv6, firstIP...)
	}

	if len(lastIP) == net.IPv4len {
		lastIP = append(v4Asv6, lastIP...)
	}
	return netWithRange{First: &firstIP, Last: &lastIP, Network: &ipNet}
}

func getPreviousIP(ip net.IP) net.IP {
	previousIP := make(net.IP, len(ip))
	copy(previousIP, ip)
	i := len(ip) - 1
	var overflow bool
	var lowerByteBound int
	if ip.To4() != nil {
		lowerByteBound = net.IPv6len - net.IPv4len
	} else {
		lowerByteBound = 0
	}
	for ; i >= lowerByteBound; i-- {
		if overflow || i == len(ip)-1 {
			previousIP[i]--
		}
		// Track if we have overflowed and thus need to continue subtracting.
		if ip[i] == 0 && previousIP[i] == 255 {
			overflow = true
		} else {
			overflow = false
		}
	}
	return previousIP
}

func getNextIP(ip net.IP) net.IP {
	nextIP := make(net.IP, len(ip))
	copy(nextIP, ip)
	i := len(ip) - 1
	var overflow bool
	var lowerByteBound int
	if ip.To4() != nil {
		lowerByteBound = net.IPv6len - net.IPv4len
	} else {
		lowerByteBound = 0
	}
	for ; i >= lowerByteBound; i-- {
		if overflow || i == len(ip)-1 {
			nextIP[i]++
		}

		if ip[i] == 255 && nextIP[i] == 0 {
			overflow = true
		} else {
			overflow = false
		}

	}
	return nextIP
}

func setNthBit(ip *[]byte, bitNum, val uint) *[]byte {
	ipCopy := make([]byte, len(*ip))
	copy(ipCopy, *ip)
	byteNum := getByteIndexOfBit(bitNum)

	if val == 0 {
		ipCopy[byteNum] = ipCopy[byteNum] & ^(1 << (bitNum % 8))
	} else if val == 1 {
		ipCopy[byteNum] = ipCopy[byteNum] | (1 << (bitNum % 8))
	} else {
		panic("set bit is not 0 or 1")
	}

	return &ipCopy
}

func createSpanningCIDR(r netWithRange) net.IPNet {
	// Don't want to modify the values of the provided range, so make copies.
	lowest := *r.First
	highest := *r.Last

	var isIPv4 bool
	var spanningMaskSize, bitLen, byteLen int
	if lowest.To4() != nil {
		isIPv4 = true
		bitLen = ipv4BitLen
		byteLen = net.IPv4len
	} else {
		bitLen = ipv6BitLen
		byteLen = net.IPv6len
	}

	if isIPv4 {
		spanningMaskSize = ipv4BitLen
	} else {
		spanningMaskSize = ipv6BitLen
	}

	// Convert to big Int  so we can easily do bitshifting on the IP addresses,
	// since golang only provides up to 64-bit unsigned integers.
	lowestBig := big.NewInt(0).SetBytes(lowest)
	highestBig := big.NewInt(0).SetBytes(highest)

	// Starting from largest mask / smallest range possible, apply a mask one bit
	// more in each iteration to the upper bound in the range  until we have
	// masked enough to pass the lower bound in the range. This
	// gives us the size of the prefix for the spanning CIDR preifx to return as
	// well as the IP for the CIDR prefix.
	for spanningMaskSize > 0 && lowestBig.Cmp(highestBig) < 0 {
		spanningMaskSize -= 1
		mask := big.NewInt(1)
		mask = mask.Lsh(mask, uint(bitLen-spanningMaskSize))
		mask = mask.Mul(mask, big.NewInt(-1))
		highestBig = highestBig.And(highestBig, mask)
	}

	// If ipv4, need to append 0s because math.Big gets rid of preceding zeroes.
	if isIPv4 {
		highest = append(ipv4LeadingZeroes, highestBig.Bytes()...)
	} else {
		highest = highestBig.Bytes()
	}

	// Int does not store leading zeroes.
	if len(highest) == 0 {
		highest = make([]byte, byteLen)
	}

	newNet := net.IPNet{IP: highest, Mask: net.CIDRMask(spanningMaskSize, bitLen)}
	return newNet
}

type netWithRange struct {
	First   *net.IP
	Last    *net.IP
	Network *net.IPNet
}

// CoalesceCIDRs transforms the provided list of CIDRs into the most-minimal equivalent set of CIDRs.
// It removes CIDRs that are subnets of other CIDRs in the list, and groups together CIDRs that have the same mask size
// into a CIDR of the same mask size provided that they share the same number of most significant mask-size bits.
//
// All IPs should be of the same type (IPv4, IPv6).
func CoalesceCIDRs(cidrs []*net.IPNet) []*net.IPNet {

	// TODO - check if all are IPv4 and IPv6
	// Convert provided networks to netWithRange structures for manipulation
	// during this function.
	ranges := []*netWithRange{}

	for _, network := range cidrs {
		newNetToRange := ipNetToRange(*network)
		ranges = append(ranges, &newNetToRange)
	}

	sort.Sort(NetsByMeta(ranges))

	// Merge adjacent CIDRs if possible.
	for i := len(ranges) - 1; i > 0; i-- {
		first1 := getPreviousIP(*ranges[i].First)

		// Since the networks are sorted, we know that if a network in the list
		// is adjacent to another one in the list, it will be the network next
		// to it in the list. If the previous IP of the current network we are
		// processing overlaps with the last IP of the previous network in the
		// list, then we can merge the two ranges together.
		if bytes.Compare(first1, *ranges[i-1].Last) <= 0 {
			// Pick the minimum of the first two IPs to represent the start
			// of the new range.
			var minFirstIP *net.IP
			if bytes.Compare(*ranges[i-1].First, *ranges[i].First) < 0 {
				minFirstIP = ranges[i-1].First
			} else {
				minFirstIP = ranges[i].First
			}

			// Always take the last IP of the ith IP.
			newRangeLast := make(net.IP, len(*ranges[i].Last))
			copy(newRangeLast, *ranges[i].Last)

			newRangeFirst := make(net.IP, len(*minFirstIP))
			copy(newRangeFirst, *minFirstIP)

			// Can't set the network field because since we are combining a
			// range of IPs, and we don't yet know what CIDR prefix(es) represent
			// the new range.
			ranges[i-1] = &netWithRange{First: &newRangeFirst, Last: &newRangeLast, Network: nil}

			// Since we have combined ranges[i] with the preceding item in the
			// ranges list, we can delete ranges[i] from the slice.
			ranges = append(ranges[:i], ranges[i+1:]...)
		}
	}

	coalescedCIDRs := []*net.IPNet{}

	// Create CIDRs from ranges that were combined if needed.
	for _, netRange := range ranges {
		// If the Network field of netWithRange wasn't modified, then we can
		// add it to the list which we will return, as it cannot be joined with
		// any other CIDR in the list.
		if netRange.Network != nil {
			coalescedCIDRs = append(coalescedCIDRs, netRange.Network)
		} else {
			// We have joined two ranges together, so we need to find the new CIDRs
			// that represent this range.
			rangeCIDRs := rangeToCIDRs(*netRange.First, *netRange.Last)
			coalescedCIDRs = append(coalescedCIDRs, rangeCIDRs...)
		}
	}

	return coalescedCIDRs
}

func rangeToCIDRs(firstIP, lastIP net.IP) []*net.IPNet {

	// First, create a CIDR that spans both IPs.
	spanningCIDR := createSpanningCIDR(netWithRange{&firstIP, &lastIP, nil})
	spanningRange := ipNetToRange(spanningCIDR)
	firstIPSpanning := spanningRange.First
	lastIPSpanning := spanningRange.Last

	cidrList := []*net.IPNet{}

	// If the first IP of the spanning CIDR passes the lower bound (firstIP),
	// we need to split the spanning CIDR and only take the IPs that are
	// greater than the value which we split on, as we do not want the lesser
	// values since they are less than the lower-bound (firstIP).
	if bytes.Compare(*firstIPSpanning, firstIP) < 0 {
		// Split on the previous IP of the first IP so that the right list of IPs
		// of the partition include the firstIP.
		prevFirstRangeIP := getPreviousIP(firstIP)
		_, _, right := partitionCIDR(spanningCIDR, net.IPNet{IP: prevFirstRangeIP, Mask: net.CIDRMask(32, 32)})
		// Append all CIDRs but the first, as this CIDR includes the upper
		// bound of the spanning CIDR, which we still need to partition on.
		cidrList = append(cidrList, right...)
		spanningCIDR = *right[0]
		cidrList = cidrList[1:]
	}

	// Conversely, if the last IP of the spanning CIDR passes the upper bound
	// (lastIP), we need to split the spanning CIDR and only take the IPs that
	// are greater than the value whcih we split on, as we do not want the greater
	// values since they are greater than the upper-bound (lastIP).
	if bytes.Compare(*lastIPSpanning, lastIP) > 0 {
		// Split on the next IP of the last IP so that the left list of IPs
		// of the partition include the lastIP.
		nextFirstRangeIP := getNextIP(lastIP)
		left, _, _ := partitionCIDR(spanningCIDR, net.IPNet{IP: nextFirstRangeIP, Mask: net.CIDRMask(32, 32)})
		cidrList = append(cidrList, left...)
	} else {
		// Otherwise, just use add the spanning CIDR to the list of networks.
		cidrList = append(cidrList, &spanningCIDR)
	}
	return cidrList
}

func partitionCIDR(targetCIDR net.IPNet, excludeCIDR net.IPNet) ([]*net.IPNet, []*net.IPNet, []*net.IPNet) {
	var targetIsIPv4 bool
	if targetCIDR.IP.To4() != nil {
		targetIsIPv4 = true
	}
	targetIPRange := ipNetToRange(targetCIDR)
	excludeIPRange := ipNetToRange(excludeCIDR)

	targetFirstIP := *targetIPRange.First
	targetLastIP := *targetIPRange.Last

	excludeFirstIP := *excludeIPRange.First
	excludeLastIP := *excludeIPRange.Last

	targetMaskSize, _ := targetCIDR.Mask.Size()
	excludeMaskSize, _ := excludeCIDR.Mask.Size()

	if bytes.Compare(excludeLastIP, targetFirstIP) < 0 {
		return nil, nil, []*net.IPNet{&targetCIDR}
	} else if bytes.Compare(targetLastIP, excludeFirstIP) < 0 {
		return []*net.IPNet{&targetCIDR}, nil, nil
	}

	if targetMaskSize >= excludeMaskSize {
		return nil, []*net.IPNet{&targetCIDR}, nil
	}

	left := []*net.IPNet{}
	right := []*net.IPNet{}

	newPrefixLen := targetMaskSize + 1

	targetFirstCopy := make(net.IP, len(targetFirstIP))
	copy(targetFirstCopy, targetFirstIP)

	iLowerOld := make(net.IP, len(targetFirstCopy))
	copy(iLowerOld, targetFirstCopy)

	// Since golang only supports up to unsigned 64-bit integers, and we need
	// to perform addition on addresses, use math/big library, which allows
	// for manipulation of large integers.
	iLower := big.NewInt(0)
	iLower = iLower.SetBytes(targetFirstCopy)

	var bitLen int

	if targetIsIPv4 {
		bitLen = ipv4BitLen
	} else {
		bitLen = ipv6BitLen
	}
	shiftAmount := (uint)(bitLen - newPrefixLen)

	targetIPInt := big.NewInt(0)
	targetIPInt.SetBytes(targetFirstIP.To16())

	iUpper := big.NewInt(0)
	exp := big.NewInt(0)
	// use left shift for exponentiation
	exp = exp.Lsh(big.NewInt(1), shiftAmount)
	iUpper = iUpper.Add(targetIPInt, exp)

	matched := big.NewInt(0)

	for excludeMaskSize >= newPrefixLen {
		// Append leading zeros to IPv4 addresses, as math.Big.Int does not
		// append them when the IP address is copied from a byte array to
		// math.Big.Int. Leading zeroes are required for parsing IPv4 addresses
		// for use with net.IP / net.IPNet.
		var iUpperBytes, iLowerBytes []byte
		if targetIsIPv4 {
			iUpperBytes = append(ipv4LeadingZeroes, iUpper.Bytes()...)
			iLowerBytes = append(ipv4LeadingZeroes, iLower.Bytes()...)
		} else {
			iUpperBytes = iUpper.Bytes()
			iLowerBytes = iLower.Bytes()
		}
		if bytes.Compare(excludeFirstIP, iUpperBytes) >= 0 {
			left = append(left, &net.IPNet{IP: iLowerBytes, Mask: net.CIDRMask(newPrefixLen, bitLen)})
			matched = matched.Set(iUpper)
		} else {
			right = append(right, &net.IPNet{IP: iUpperBytes, Mask: net.CIDRMask(newPrefixLen, bitLen)})
			matched = matched.Set(iLower)
		}

		newPrefixLen += 1

		if newPrefixLen > bitLen {
			break
		}

		iLower = iLower.Set(matched)
		iUpper = iUpper.Add(matched, big.NewInt(0).Lsh(big.NewInt(1), uint(bitLen-newPrefixLen)))

	}
	excludeList := []*net.IPNet{&excludeCIDR}

	return left, excludeList, right
}
