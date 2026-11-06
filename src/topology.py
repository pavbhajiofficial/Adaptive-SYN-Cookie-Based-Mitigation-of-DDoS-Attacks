"""
topology.py
Builds the base Mininet topology for the DDoS case study:
one switch connecting a server host, two legitimate student hosts,
and one attacker host.
"""

from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel


def build_topology():
    net = Mininet(controller=OVSController)
    net.addController('c0')

    server = net.addHost('server')    # simulated exam-results portal
    h1 = net.addHost('h1')            # legitimate student
    h2 = net.addHost('h2')            # legitimate student
    attacker = net.addHost('attacker')  # DDoS source

    s1 = net.addSwitch('s1')

    for host in [server, h1, h2, attacker]:
        net.addLink(host, s1)

    net.start()
    print('Testing connectivity between all hosts...')
    net.pingAll()

    print('\nTopology is up. Useful next commands inside the mininet> prompt:')
    print('  server python3 server.py &')
    print('  h1 python3 client_normal.py')
    print('  attacker python3 attack_synflood.py')
    print('  server tcpdump -i server-eth0 -w capture.pcap &\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build_topology()
