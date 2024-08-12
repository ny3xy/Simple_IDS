from threading import Thread
from ids.packet import Packet
from ids.rule import Rule
from scapy.all import (
    sniff,
    TCP,
    UDP,
    IP,
    IPv6,
    ICMP,
    DNS
)
from scapy.layers import (http)

class IDS(Thread):
    def __init__(self, rules: list[Rule]) -> None:
        Thread.__init__(self)
        self.stopped = False
        self.rules = rules

    def stop(self):
        self.stopped = True

    def _is_stopped(self) -> bool:
        return self.stopped

    def _filter(self, raw_packet):
        if IP in raw_packet or IPv6 in raw_packet:
            protocol = IP if IP in raw_packet else IPv6
            communication_protocol = 'IP' if protocol is IP else 'IPv6'
            transmission_protocol = 'TCP' if TCP in raw_packet else 'UDP' if UDP in raw_packet else 'UNKNWN'
            protocol_str = 'UNKNWN'
            if DNS in raw_packet:
                protocol_str = 'DNS'
            elif ICMP in raw_packet:
                protocol_str = 'ICMP'
            elif raw_packet.haslayer(http.HTTPRequest):
                protocol_str = 'HTTP'
            src = raw_packet[protocol].src
            sport = 0 if not hasattr(raw_packet, 'sport') else int(raw_packet.sport)
            dst = raw_packet[protocol].dst
            dport = 0 if not hasattr(raw_packet, 'dport') else int(raw_packet.dport)

            packet = Packet(
                src,
                sport,
                dst,
                dport,
                protocol_str,
                transmission_protocol,
                communication_protocol
            )
            self._check_packet(packet)

    def _check_packet(self, packet: Packet):
        for rule in self.rules:
            if rule.match(packet):
                rule.perform_action(packet)
                return rule
        return None

    def run(self):
        sniff(prn=self._filter, filter='', store=0, stop_filter=self._is_stopped)