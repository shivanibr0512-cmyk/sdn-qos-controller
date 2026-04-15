# Packet Drop Simulator - POX Controller
# Blocks traffic from h3 (10.0.0.3) to h2 (10.0.0.2)

from pox.core import core
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# DROP RULE CONFIG
BLOCKED_SRC = '10.0.0.3'  # h3
BLOCKED_DST = '10.0.0.2'  # h2

class PacketDropController(object):

    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)
        self.install_drop_rules()
        log.info("PacketDropController connected to switch")

    def install_drop_rules(self):
        # Install DROP rule: h3 -> h2
        msg = of.ofp_flow_mod()
        msg.priority = 100  # High priority
        msg.match.dl_type = 0x0800  # IPv4
        msg.match.nw_src = IPAddr(BLOCKED_SRC)
        msg.match.nw_dst = IPAddr(BLOCKED_DST)
        # No actions = DROP
        self.connection.send(msg)
        log.info("DROP rule installed: %s -> %s", BLOCKED_SRC, BLOCKED_DST)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        self.mac_to_port[packet.src] = event.port

        # Flood if destination unknown
        if packet.dst not in self.mac_to_port:
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
        else:
            out_port = self.mac_to_port[packet.dst]
            msg = of.ofp_flow_mod()
            msg.priority = 10
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)

class PacketDrop(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        PacketDropController(event.connection)
        log.info("Switch connected")

def launch():
    core.registerNew(PacketDrop)
    log.info("Packet Drop Simulator started")