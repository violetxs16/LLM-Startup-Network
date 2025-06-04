#!/usr/bin/python


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController


class final_topo(Topo):
  def build(self):
    #Create Switches
    core = self.addSwitch('core', dpid = 1)
    f1s1 = self.addSwitch('f1s1', dpid = 2)
    f1s2 = self.addSwitch('f1s2', dpid = 3)
    f2s1 = self.addSwitch('f2s1', dpid = 4)
    f2s2 = self.addSwitch('f2s2', dpid = 5)
    dcs = self.addSwitch('dcs', dpid = 6)
    #Connect switches to switches
    self.addLink(core, f1s1, port1 = 22, port2 = 20) #first floor switch 1 to core switch
    self.addLink(core, f1s2, port1 = 23, port2 = 20) #first floor switch 2 to core switch
    self.addLink(core, f2s1, port1 = 24, port2 = 20) #second floor switch 1 to core switch
    self.addLink(core, f2s2, port1 = 25, port2 = 20) #second floor switch 2 to core switch
    self.addLink(core, dcs, port1 = 26, port2 = 20) #data center switch to core switch


    #Create hosts
    #hosts connected directly to core
    h_untrust = self.addHost('h_untrust', mac='00:00:00:00:00:09', ip='108.35.24.113/24', defaultRoute="h_untrust-eth0")
    h_trust = self.addHost('h_trust', mac='00:00:00:00:00:10', ip='192.47.38.109/24', defaultRoute="h_trust-eth0")
    h_server = self.addHost('h_server', mac='00:00:00:00:00:11', ip='128.114.3.178/24', defaultRoute="h_server-eth0")


    #Floor 1 hosts
    h101 = self.addHost('h101', mac='00:00:00:00:00:01', ip='128.114.1.101/24', defaultRoute="h101-eth0")
    h102 = self.addHost('h102', mac='00:00:00:00:00:02', ip='128.114.1.102/24', defaultRoute="h102-eth0")
    h103 = self.addHost('h103', mac='00:00:00:00:00:03', ip='128.114.1.103/24', defaultRoute="h103-eth0")
    h104 = self.addHost('h104', mac='00:00:00:00:00:04', ip='128.114.1.104/24', defaultRoute="h104-eth0")


    #Floor 2 hosts
    h201 = self.addHost('h201', mac='00:00:00:00:00:05', ip='128.114.2.201/24', defaultRoute="h201-eth0")
    h202 = self.addHost('h202', mac='00:00:00:00:00:06', ip='128.114.2.202/24', defaultRoute="h202-eth0")
    h203 = self.addHost('h203', mac='00:00:00:00:00:07', ip='128.114.2.203/24', defaultRoute="h203-eth0")
    h204 = self.addHost('h204', mac='00:00:00:00:00:08', ip='128.114.2.204/24', defaultRoute="h204-eth0")

    #connect hosts to switches
    #floor 1 switch 1

    self.addLink(f1s1, h101, port1 = 1, port2 = 0) #plug cable into port 1 of switch & plug same cable in port 0 of host. 
    self.addLink(f1s1, h102, port1 = 2, port2 = 0)

    #floor 1 switch 2
    self.addLink(f1s2, h103, port1 = 1, port2 = 0)
    self.addLink(f1s2, h104, port1 = 2, port2 = 0)

    #floor 2 switch 1
    self.addLink(f2s1, h201, port1 = 1, port2 = 0)
    self.addLink(f2s1, h202, port1 = 2, port2 = 0)

    #floor 2 switch 2
    self.addLink(f2s2, h203, port1 = 1, port2 = 0)
    self.addLink(f2s2, h204, port1 = 2, port2 = 0)

    #data center switch
    self.addLink(dcs, h_server, port1 = 1, port2 = 0)

    #direct connection
    self.addLink(core, h_trust, port1 = 20, port2 = 0)
    self.addLink(core, h_untrust, port1 = 21, port2 = 0)

    




def configure():
  topo = final_topo()
  net = Mininet(topo=topo, controller=RemoteController)
  net.start()


  CLI(net)
 
  net.stop()




if __name__ == '__main__':
  configure()
