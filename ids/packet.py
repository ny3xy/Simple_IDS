from dataclasses import dataclass


@dataclass
class Packet:
    src: str
    sport: int
    dst: str
    dport: int
    protocol: str
    transmission_protocol: str
    communication_protocol: str

    def __hash__(self):
        return hash(
            (
                self.src,
                self.sport,
                self.dst,
                self.dport,
                self.protocol,
                self.transmission_protocol,
                self.communication_protocol
            )
        )