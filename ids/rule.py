from dataclasses import dataclass
from ids.packet import Packet
from pprint import pprint
import shlex
import logging


@dataclass
class Rule:
    action: str
    protocol: str
    src: str
    sport: str
    dst: str
    dport: str
    message: str
    results = None

    def match(self, packet: Packet):
        if self.results is None:
            self.results = {}
        packet_hash = hash(packet)
        if packet_hash in self.results:
            return self.results[packet_hash]
        same_protocol = self.protocol.lower() in (packet.protocol.lower(), 'any')
        same_src = self.src in (packet.src, 'any')
        if self.src[0] == '!':
            same_src = self.src[1:] != packet.src
        same_sport = self.sport in (str(packet.sport), 'any')
        same_dst = self.dst in (packet.dst, 'any')
        if self.dst[0] == '!':
            same_dst = self.dst[1:] != packet.dst
        same_dport = self.dport in (str(packet.dport), 'any')
        result = False
        if same_protocol and same_src and same_sport and same_dst and same_dport:
            result = True
        self.results[packet_hash] = result
        return result

    def perform_action(self, packet: Packet):
        match self.action:
            case 'alert':
                pass
            case 'print':
                pprint({
                    'packet': packet,
                    'rule': self
                })
            case 'log':
                logger = logging.getLogger('Simple_IDS')
                logger.info({
                    'packet': packet,
                    'rule': self
                })


class RuleReader:
    @classmethod
    def read(cls, file_name: str):
        rules = []
        with open(file_name, 'r') as f:
            rule_strings = f.read().split('\n')
            for i, rule_string in enumerate(rule_strings):
                sentence = shlex.split(rule_string)
                if len(sentence) != 6:
                    logging.error(f'Cannot parse rule @ line num: #{i+1}, incorrect format.')
                    continue
                action = sentence[4]
                if action not in ('alert', 'print', 'log', 'callback'):
                    logging.error(f'Cannot parse rule @ line num: #{i+1}, cannot recognise action \'{action}\'.')
                    continue
                source = sentence[1].split(':')
                src = source[0]
                sport = source[1]
                destination = sentence[3].split(':')
                dst = destination[0]
                dport = destination[1]
                message = sentence[5]
                protocol = sentence[0]
                rules.append(
                    Rule(
                        action,
                        protocol,
                        src,
                        sport,
                        dst,
                        dport,
                        message
                    )
                )
        return rules