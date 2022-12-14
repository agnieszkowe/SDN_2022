#!/usr/bin/env python

"""
This example shows how to create an empty Mininet object
(without a topology object) and add nodes to it manually.
"""

from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def emptyNet():

    "Create an empty network and add nodes to it."

    net = Mininet( controller=RemoteController )

    info( '*** Adding controller\n' )
    net.addController( 'c0' , controller=RemoteController, ip="127.0.0.1", port=6633 )

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'h1', mac='00:00:00:00:00:01') 
    h2 = net.addHost( 'h2', mac='00:00:00:00:00:02')
    h3 = net.addHost( 'h3', mac='00:00:00:00:00:03') 
    h4 = net.addHost( 'h4', mac='00:00:00:00:00:04')
    h5 = net.addHost( 'h5', mac='00:00:00:00:00:05') # generowanie ruchu

    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1', mac='00:00:00:00:00:11')
    s2 = net.addSwitch( 's2', mac='00:00:00:00:00:21')
    s3 = net.addSwitch( 's3', mac='00:00:00:00:00:31')

    info( '*** Creating links\n' )
    net.addLink( h1, s1 )
    net.addLink( h2, s1 )
    net.addLink( s1, s2 )
    net.addLink( s1, s3 )
    net.addLink( h3, s2 )
    net.addLink( h4, s3 )
    net.addLink( h5, s1 )
    net.addLink( h5, s2 )
    net.addLink( h5, s3 )

    info( '*** Starting network\n')
    net.start()

    info( '*** Running CLI\n' )
    CLI( net )

    info( '*** Stopping network' )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    emptyNet()
