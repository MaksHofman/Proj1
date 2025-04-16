from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

def setup_routing(r1, r2, h1, h2):
    """Configure static IP addresses and routing."""

    # Enable IP forwarding on routers
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")
    r2.cmd("sysctl -w net.ipv4.ip_forward=1")

    # Router 1: Add IP addresses
    r1.cmd("ip addr flush dev r1-eth0")
    r1.cmd("ip addr add 10.0.1.2/24 dev r1-eth0")  # h1-r1
    r1.cmd("ip addr flush dev r1-eth1")
    r1.cmd("ip addr add 10.0.2.1/24 dev r1-eth1")  # r1-r2
    r1.cmd("ip link set r1-eth0 up")
    r1.cmd("ip link set r1-eth1 up")

    # Router 2: Add IP addresses
    r2.cmd("ip addr flush dev r2-eth0")
    r2.cmd("ip addr add 10.0.3.2/24 dev r2-eth0")  # h2-r2
    r2.cmd("ip addr flush dev r2-eth1")
    r2.cmd("ip addr add 10.0.2.2/24 dev r2-eth1")  # r1-r2
    r2.cmd("ip link set r2-eth0 up")
    r2.cmd("ip link set r2-eth1 up")

    # Host 1: Assign IP and set default gateway
    h1.cmd("ip addr flush dev h1-eth0")
    h1.cmd("ip addr add 10.0.1.1/24 dev h1-eth0")
    h1.cmd("ip route add default via 10.0.1.2")
    h1.cmd("ip link set h1-eth0 up")

    # Host 2: Assign IP and set default gateway
    h2.cmd("ip addr flush dev h2-eth0")
    h2.cmd("ip addr add 10.0.3.1/24 dev h2-eth0")
    h2.cmd("ip route add default via 10.0.3.2")
    h2.cmd("ip link set h2-eth0 up")

    # Routers: Add static routes
    r1.cmd("ip route add 10.0.3.0/24 via 10.0.2.2")  # Route to h2 via r2
    r2.cmd("ip route add 10.0.1.0/24 via 10.0.2.1")  # Route to h1 via r1

if __name__ == '__main__':
    setLogLevel('info')

    # Create Mininet network
    net = Mininet(link=TCLink)

    # Add nodes
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    r1 = net.addHost('r1', ip=None)  # Router 1
    r2 = net.addHost('r2', ip=None)  # Router 2

    # Add links
    net.addLink(h1, r1)  # h1-r1
    net.addLink(h2, r2)  # h2-r2
    net.addLink(r1, r2)  # r1-r2

    # Start network
    net.start()

    # Configure routing
    setup_routing(r1, r2, h1, h2)

    # Enter CLI
    CLI(net)

    # Stop network
    net.stop()
