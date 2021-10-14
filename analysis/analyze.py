#!/usr/bin/env python3

"""template.py module description."""


import argparse
import csv
import sys


default_values = {
    'debug': 0,
    'infile': None,
}


def do_something(options):
    # read input file (csv)
    reader = csv.reader(open(options.infile), delimiter=',')

    bede_rtp = 0
    bede_nonrtp = 0
    nonrtp_150100000000 = 0
    nonrtp_unknown = []

    first_row = True
    for row in reader:
        if len(row) == 0:
            # empty line
            continue
        elif first_row:
            first_row = False
            # get row names
            row_names = row
            if row_names[0].startswith('#'):
                row_names[0] = row_names[0][1:]
            continue
        # do something with the packet
        udp_payload = row[4]
        if 'bede' in udp_payload:
            # likely RTP: cut at 12 bytes before bede
            bede_index = udp_payload.index('bede')
            rtp_index = bede_index - 24
            if rtp_index < 0:
                bede_nonrtp += 1
                continue
            # prop_header = udp_payload[:rtp_index]
            rtp_header = udp_payload[rtp_index:]
            rtp_version = (int(rtp_header[0:2], 16) & 0xc0) >> 6
            if rtp_version != 2:
                bede_nonrtp += 1
                continue
            bede_rtp += 1
        elif '150100000000' in udp_payload:
            nonrtp_150100000000 += 1
        else:
            # unknown packet: store it
            nonrtp_unknown.append(row)

    # print results
    print('# non-rtp')
    print('nonrtp_150100000000: %i' % nonrtp_150100000000)
    print('nonrtp_unknown: %i' % len(nonrtp_unknown))
    print('# rtp')
    print('bede_rtp: %r' % bede_rtp)
    print('bede_nonrtp: %r' % bede_nonrtp)


def get_options(argv):
    """Generic option parser.

    Args:
        argv: list containing arguments

    Returns:
        Namespace - An argparse.ArgumentParser-generated option object
    """
    # init parser
    # usage = 'usage: %prog [options] arg1 arg2'
    # parser = argparse.OptionParser(usage=usage)
    # parser.print_help() to get argparse.usage (large help)
    # parser.print_usage() to get argparse.usage (just usage line)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
            '-d', '--debug', action='count',
            dest='debug', default=default_values['debug'],
            help='Increase verbosity (use multiple times for more)',)
    parser.add_argument(
            '--quiet', action='store_const',
            dest='debug', const=-1,
            help='Zero verbosity',)
    parser.add_argument(
            'infile', type=str,
            default=default_values['infile'],
            metavar='input-file',
            help='input file',)
    # do the parsing
    options = parser.parse_args(argv[1:])
    return options


def main(argv):
    # parse options
    options = get_options(argv)
    # get infile
    if options.infile == '-':
        options.infile = '/dev/fd/0'
    # print results
    if options.debug > 0:
        print(options)
    # do something
    do_something(options)


if __name__ == '__main__':
    # at least the CLI program name: (CLI) execution
    main(sys.argv)
