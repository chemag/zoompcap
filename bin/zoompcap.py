#!/usr/bin/env python3

# https://stackoverflow.com/questions/23566710/saving-packets-to-a-pcap-file-using-pcapy
# https://rawgit.com/CoreSecurity/pcapy/master/pcapy.html

import sys
import pcapy
import impacket.ImpactDecoder


# global variables to pass to the pcapy callback
l2_decoder = None
dumper = None
dumper_full = None
dumper_rem = None

debug = 2

counter = 0


def printf_payload(in_bin, max_bytes):
    out = ''
    for i in range(min(max_bytes, len(in_bin))):
        out += '%02x ' % in_bin[i]
    return out


def pkt_callback(hdr, data):
    global debug
    global counter

    counter += 1

    try:
        ethpkt = l2_decoder.decode(data)
        if debug > 2:
            print('hdr: ', hdr)
            print('data: ', data)
            print('ethpkt: ', ethpkt)
    except impacket.ImpactPacket.ImpactPacketException:
        print('error: cannot decode packet %i' % counter)
        if debug > 0:
            dumper_rem.dump(hdr, data)
        return

    # ignore non-ip packets
    if ethpkt.get_ether_type() not in (0x0800, 0x86dd):
        if debug > 0:
            print('info: non-ip packet (ethertype: 0x%04x)' %
                  ethpkt.get_ether_type())
        if debug > 0:
            dumper_rem.dump(hdr, data)
        return

    # ignore non-udp packets
    ippkt = ethpkt.child()
    if ippkt.__class__ is impacket.IP6.IP6:
        proto = ippkt.get_next_header()
    else:
        proto = ippkt.get_ip_p()

    if proto != 17:
        if debug > 1:
            print('info: non-udp packet (ip.proto: 0x%02x)' % proto)
        if debug > 0:
            dumper_rem.dump(hdr, data)
        return

    # get the UDP payload
    udppkt = ippkt.child()
    udppayload = udppkt.child()
    udppayload_bin = udppayload.get_packet()

    # get the UDP payload
    zhdr_len = 0
    if b'\xbe\xde' not in udppayload_bin:
        # no Generic RTP Header Extension: ignore packet
        if debug > 1:
            udppayload_bin_str = printf_payload(udppayload_bin, 4)
            print('info: non-bede packet (payload: %s)' % udppayload_bin_str)
        if debug > 0:
            dumper_rem.dump(hdr, data)
        return

    bede_index = udppayload_bin.index(b'\xbe\xde')
    rtp_index = bede_index - 12

    # make sure this looks like RTP (check for version 2)
    rtp_version = (udppayload_bin[rtp_index] & 0xc0) >> 6
    if rtp_version != 2:
        # no valid RTP version: ignore packet
        if debug > 1:
            udppayload_bin_str = printf_payload(udppayload_bin, 4)
            print('info: non-rtp packet (payload: %s)' % udppayload_bin_str)
        if debug > 0:
            dumper_rem.dump(hdr, data)
        return

    # store a copy of the original packet
    if debug > 1:
        dumper_full.dump(hdr, data)

    # look for the generic RTP header extension marker
    zhdr_len = rtp_index
    udppayload_bin = udppayload_bin[zhdr_len:]
    # set the cut UDP payload
    udppayload.set_bytes_from_string(udppayload_bin)

    # remove the zhdr_len characters from the header
    hdr.setlen(hdr.getlen() - zhdr_len)
    hdr.setcaplen(hdr.getcaplen() - zhdr_len)

    # remove the zhdr_len characters from the IP and UDP header lengths
    udppkt.set_uh_ulen(udppkt.get_uh_ulen() - zhdr_len)

    if ippkt.__class__ is impacket.IP6.IP6:
        proto = ippkt.get_next_header()
    else:
        ippkt.set_ip_len(ippkt.get_ip_len() - zhdr_len)
        # TODO(chemag): fix IP checksum

    # packet is zoom: store it
    data = ethpkt.get_packet()
    dumper.dump(hdr, data)


def main(argv):
    global l2_decoder
    global dumper
    global dumper_rem
    global dumper_full

    # assume `./filter.py in.pcap out.pcap`
    infile = sys.argv[1]
    outfile = sys.argv[2]

    # set input file
    pc = pcapy.open_offline(infile)
    datalink = pc.datalink()
    if datalink == pcapy.DLT_EN10MB:
        l2_decoder = impacket.ImpactDecoder.EthDecoder()
    elif datalink == pcapy.DLT_LINUX_SLL:
        l2_decoder = impacket.ImpactDecoder.LinuxSSLDecoder()
    else:
        print('unknown datalink: %i' % datalink)
        sys.exit(-1)

    # set output file(s)
    dumper = pc.dump_open(outfile)
    if debug > 0:
        dumper_rem = pc.dump_open(outfile + '.rem.pcap')
    if debug > 1:
        dumper_full = pc.dump_open(outfile + '.full.pcap')

    # loop through all the packets
    packet_limit = -1  # infinite
    try:
        pc.loop(packet_limit, pkt_callback)  # capture packets
    except pcapy.PcapError as ee:
        if 'truncated dump file' in ee.args[0]:
            # truncated file: ignore the issue
            pass
        else:
            raise



if __name__ == "__main__":
    # at least the CLI program name: (CLI) execution
    main(sys.argv)
