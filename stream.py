__author__ = 'michaelbaker'

import sys
import traceback
import argparse
import nids
import hashlib
import datetime

from conversation import Conversation
from filedissector import FileDissector


class StreamProcess():

    def parse_args(self):
        ap = argparse.ArgumentParser(description=__doc__)
        ap.add_argument('-r', dest='filename', help='The pcap file to process')
        ap.add_argument('-i', dest='interface', help='The interface to listen on.')
        ap.add_argument('-e', dest='extract', action='store_true', help='Extract files to the extract directory')
        ap.add_argument('--debug', dest='debug', action='store_true', default=False, help='Print output to stdout')
        return ap.parse_args()

    def run(self, config):
        self.config = config
        self.stream_handler = StreamHandler(self.config)

        nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksumming
        nids.param('scan_num_hosts', 0)  # disable portscan detection

        if self.config.filename:
            nids.param('filename', self.config.filename)
        else:
            nids.param('device', self.config.interface)

        nids.init()
        nids.register_tcp(self.stream_handler.tcp_callback)
        #nids.register_udp(self.stream_handler.udp_callback)

        try:
            nids.run()
        except nids.error, e:
            print >> sys.stderr, 'nids/pcap error:', e
            print >> sys.stderr, 'Error in %s' % self.filename
            traceback.print_exc(file=sys.stderr)
            #sys.exit(-1)
        except Exception, e:
            print >> sys.stderr, 'Exception', e
            traceback.print_exc(file=sys.stderr)
            sys.exit(-1)

class StreamHandler:

    END_STATES = {
        nids.NIDS_CLOSE: 'close',
        nids.NIDS_TIMEOUT: 'timeout',
        nids.NIDS_RESET: 'reset',
    }

    def __init__(self, config):
        print "Processing"
        self.config = config
        self.tcp_debug = False
        self.udp_debug = False
        self.print_shellcode = True
        self.flows = {}

    def tcp_callback(self, tcp):
        # Established
        if tcp.nids_state == nids.NIDS_JUST_EST:
            (saddr, sport), (daddr, dport) = tcp.addr
            tcp.client.collect = 1
            tcp.server.collect = 1

            flow = hashlib.sha1(str(tcp.addr)).hexdigest()
            self.flows[flow] = Conversation()
            self.flows[flow].addresses = tcp.addr

            if self.tcp_debug:
                print "Conversation established at -> {}".format(nids.get_pkt_ts())
        # Data received
        elif tcp.nids_state == nids.NIDS_DATA:
            (saddr, sport), (daddr, dport) = tcp.addr

            flow = hashlib.sha1(str(tcp.addr)).hexdigest()

            if tcp.client.data[:tcp.client.count_new]:
                '''This is data from the Server to the Client'''
                client_data = len(tcp.client.data[:tcp.client.count_new])
                self.flows[flow].bpackets.append(client_data)
                self.flows[flow].btimestamps.append(nids.get_pkt_ts())
            elif tcp.server.data[:tcp.server.count_new]:
                '''This is data from the Client to the Server'''
                server_data = len(tcp.server.data[:tcp.server.count_new])
                self.flows[flow].fpackets.append(server_data)
                self.flows[flow].ftimestamps.append(nids.get_pkt_ts())

            tcp.discard(0)

            if self.tcp_debug:
                print "Data sent at {}: {} -> {}".format(nids.get_pkt_ts(), saddr, daddr)

        elif tcp.nids_state in self.END_STATES:
            (saddr, sport), (daddr, dport) = tcp.addr

            flow = hashlib.sha1(str(tcp.addr)).hexdigest()
            self.flows[flow].fdata = tcp.server.data[:tcp.server.count]
            self.flows[flow].bdata = tcp.client.data[:tcp.client.count]
            self.emit(self.flows[flow], tcp.addr)

            if self.tcp_debug:
                print "Conversation ended at {} {} -> {} ({}) Server -> {} Client -> {}".format(nids.get_pkt_ts(), saddr, daddr, dport,
                                                                      len(tcp.client.data[:tcp.client.count]), len(tcp.server.data[:tcp.server.count]))

    def emit(self, conversation, addrs):
        (saddr, sport), (daddr, dport) = addrs

        start, stop = conversation.first_and_last

        print "{} Start {} Stop {} Duration {} C2S {} ({}) S2C {} ({})".format(conversation.addresses,
                                    datetime.datetime.fromtimestamp(start), datetime.datetime.fromtimestamp(stop), conversation.duration,
                                    sum(conversation.fpackets), FileDissector.just_guess(conversation.fdata),
                                    sum(conversation.bpackets), FileDissector.just_guess(conversation.bdata))

        if FileDissector.just_guess(conversation.fdata) and FileDissector.just_guess(conversation.bdata) == 'text/plain':
            client = conversation.fdata.split("\n")
            server = conversation.bdata.split("\n")
            '''
            print "##### CLIENT TO SERVER #####"
            for c in client:
                print c

            print "##### SERVER TO CLIENT #####"
            for s in server:
                print s
            '''
            print "##### INTERLEAVED #####"
            for c, s in zip(client, server):
                print s
                print c

        if FileDissector.just_guess(conversation.fdata) == 'application/octet-stream' or 'application/x-dosexec':
            FileDissector.guess_from_file(conversation.fdata)
            FileDissector.pe_info(conversation.fdata)

        state, msg = FileDissector.is_it_shellcode(conversation.fdata)
        if state:
            print "[+] Shellcode found"
            if self.print_shellcode:
                emulated = FileDissector.show_me_shellcode(conversation.fdata)
                print emulated

        if FileDissector.just_guess(conversation.bdata) == 'application/octet-stream' or 'application/x-dosexec':
            FileDissector.guess_from_file(conversation.bdata)
            FileDissector.pe_info(conversation.bdata)

        state, msg = FileDissector.is_it_shellcode(conversation.bdata)
        if state:
            print "[+] Shellcode found"
            if self.print_shellcode:
                emulated = FileDissector.show_me_shellcode(conversation.bdata)
                print emulated

    def udp_callback(self, addrs, payload, pkt):
        (saddr, sport), (daddr, dport) = addrs
        if self.udp_debug:
            print "UDP Packet -> {}".format(nids.get_pkt_ts())
