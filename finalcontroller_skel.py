# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def send_packet_format(self, packet_in, out_port, match_criteria):
    # Packet handling
    packet_out = of.ofp_packet_out()
    packet_out.data = packet_in
    packet_out.actions.append(of.ofp_action_output(port=out_port))
    self.connection.send(packet_out)
    
    # Rule creation
    rule = of.ofp_flow_mod()
    rule.actions.append(of.ofp_action_output(port=out_port))
    rule.match = match_criteria
    rule.idle_timeout = of.OFP_FLOW_PERMANENT
    self.connection.send(rule)

  def drop_packet_format(self, packet_in, match_criteria):
      # Drop the current packet
      packet_out = of.ofp_packet_out()
      packet_out.data = packet_in
      self.connection.send(packet_out)
      
      # Create rule to drop future packets
      rule = of.ofp_flow_mod()
      # No actions means packet is dropped
      rule.match = match_criteria
      rule.idle_timeout = of.OFP_FLOW_PERMANENT
      self.connection.send(rule)

  def do_final(self, packet, packet_in, port_on_switch, switch_id):
    #determine what type of packet is coming in: ICMP, TCP?
    if(switch_id == '0000000000000001'): #core switch -> all main logic will be here
        if(packet.find('icmp')):
            #step 1: get header information
            header = packet.find('ipv4')

            #check if packet is from untrusted host -> drop all packets
            if(header.srcip == '108.35.24.113'):
                if(header.dstip == '192.47.38.109'):  #untrusted host can send to trusted host
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_src = '108.35.24.113', nw_dst = '192.47.38.109')
                    self.send_packet_format(packet_in, 20, match)
                else:  #untrusted host to internal hosts - drop
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_src = '108.35.24.113')
                    self.drop_packet_format(packet_in, match)
                    
            elif(header.srcip == '192.47.38.109'):
                #trusted host can only send packets to floor 1 and untrusted host
                if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102'):
                    #floor 1 switch 1
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_dst = header.dstip, nw_src = '192.47.38.109')
                    self.send_packet_format(packet_in, 22, match)
                    
                elif(header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                    #floor 1 switch 2
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_dst = header.dstip, nw_src = '192.47.38.109')
                    self.send_packet_format(packet_in, 23, match)
                elif(header.dstip == '108.35.24.113'):
                    #trusted to untrusted host
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_dst = header.dstip, nw_src = '192.47.38.109')
                    self.send_packet_format(packet_in, 21, match)
                else:
                    #trusted host cannot send packets to floor 2 or server - drop
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_dst = header.dstip, nw_src = '192.47.38.109')
                    self.drop_packet_format(packet_in, match)
            
            #block icmp between department a and department b
            elif(header.srcip == '128.114.1.101' or header.srcip == '128.114.1.102' or 
                 header.srcip == '128.114.1.103' or header.srcip == '128.114.1.104'):
                #department a to department b - block
                if(header.dstip == '128.114.2.201' or header.dstip == '128.114.2.202' or
                   header.dstip == '128.114.2.203' or header.dstip == '128.114.2.204'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_src = header.srcip, nw_dst = header.dstip)
                    self.drop_packet_format(packet_in, match)
                else:
                    #allow other icmp from department a
                    if(header.dstip == '108.35.24.113'):  #to untrusted host
                        match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '108.35.24.113')
                        self.send_packet_format(packet_in, 21, match)
                    elif(header.dstip == '192.47.38.109'):  #to trusted host
                        match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '192.47.38.109')
                        self.send_packet_format(packet_in, 20, match)
                    elif(header.dstip == '128.114.3.178'):  #to server
                        match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '128.114.3.178')
                        self.send_packet_format(packet_in, 26, match)
                    else:
                        #route to appropriate floor 1 switch
                        if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102'):
                            match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                            self.send_packet_format(packet_in, 22, match)
                        elif(header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                            match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                            self.send_packet_format(packet_in, 23, match)
            
            elif(header.srcip == '128.114.2.201' or header.srcip == '128.114.2.202' or
                 header.srcip == '128.114.2.203' or header.srcip == '128.114.2.204'):
                #department b to department a - block
                if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102' or
                   header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, 
                                      nw_src = header.srcip, nw_dst = header.dstip)
                    self.drop_packet_format(packet_in, match)
                else:
                    #allow other icmp from department b
                    if(header.dstip == '108.35.24.113'):  #to untrusted host
                        match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '108.35.24.113')
                        self.send_packet_format(packet_in, 21, match)
                    elif(header.dstip == '192.47.38.109'):  #to trusted host
                        match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '192.47.38.109')
                        self.send_packet_format(packet_in, 20, match)
                    elif(header.dstip == '128.114.3.178'):  #to server
                        match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '128.114.3.178')
                        self.send_packet_format(packet_in, 26, match)
                    else:
                        #route to appropriate floor 2 switch
                        if(header.dstip == '128.114.2.201' or header.dstip == '128.114.2.202'):
                            match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                            self.send_packet_format(packet_in, 24, match)
                        elif(header.dstip == '128.114.2.203' or header.dstip == '128.114.2.204'):
                            match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                            self.send_packet_format(packet_in, 25, match)
                            
            elif(header.dstip == '108.35.24.113'):  #forward packets to untrusted host
                match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '108.35.24.113')
                self.send_packet_format(packet_in, 21, match)  
            elif(header.dstip == '192.47.38.109'):
                match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = '192.47.38.109')
                self.send_packet_format(packet_in, 20, match)    
            else:  #forward packets to routers
                #need to check which port to send to
                #5 different cases
                #send to f1s1
                if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 22, match)
                #send to f1s2
                elif(header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 23, match)
                #send to f2s1
                elif(header.dstip == '128.114.2.201' or header.dstip == '128.114.2.202'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 24, match)
                #send to f2s2
                elif(header.dstip == '128.114.2.203' or header.dstip == '128.114.2.204'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 25, match)
                #send to dcs
                elif(header.dstip == '128.114.3.178'):
                    match = of.ofp_match(dl_type = 0x0800, nw_proto = of.ICMP, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 26, match)
                    
        elif(packet.find('ipv4')):
            #step 1: get header information
            header = packet.find('ipv4')
            #case 1: untrusted host 
            if(header.srcip == '108.35.24.113'):
                #untrusted host to server - block all ip traffic
                if(header.dstip == '128.114.3.178'):
                  match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.3.178', nw_src = '108.35.24.113')
                  self.drop_packet_format(packet_in, match)
                else: #untrusted host to other hosts - allow
                  #core needs to determine which port to send to
                  #send to f1s1
                  if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '108.35.24.113')
                      self.send_packet_format(packet_in, 22, match)
                  #send to f1s2
                  elif(header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '108.35.24.113')
                      self.send_packet_format(packet_in, 23, match)
                  #send to f2s1
                  elif(header.dstip == '128.114.2.201' or header.dstip == '128.114.2.202'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '108.35.24.113')
                      self.send_packet_format(packet_in, 24, match)
                  #send to f2s2
                  elif(header.dstip == '128.114.2.203' or header.dstip == '128.114.2.204'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '108.35.24.113')
                      self.send_packet_format(packet_in, 25, match)
                  #send to trusted host
                  elif(header.dstip == '192.47.38.109'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '108.35.24.113')
                      self.send_packet_format(packet_in, 20, match)
                      
            elif(header.srcip == '192.47.38.109'):
                #trusted host to server - block all ip traffic
                if(header.dstip == '128.114.3.178'):
                  match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.3.178', nw_src = '192.47.38.109')
                  self.drop_packet_format(packet_in, match)
                else: #trusted host to other hosts
                  #send to f1s1
                  if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '192.47.38.109')
                      self.send_packet_format(packet_in, 22, match)
                  #send to f1s2
                  elif(header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '192.47.38.109')
                      self.send_packet_format(packet_in, 23, match)
                  #send to f2s1
                  elif(header.dstip == '128.114.2.201' or header.dstip == '128.114.2.202'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '192.47.38.109')
                      self.send_packet_format(packet_in, 24, match)
                  #send to f2s2
                  elif(header.dstip == '128.114.2.203' or header.dstip == '128.114.2.204'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '192.47.38.109')
                      self.send_packet_format(packet_in, 25, match)
                  #send to untrusted host
                  elif(header.dstip == '108.35.24.113'):
                      match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip, nw_src = '192.47.38.109')
                      self.send_packet_format(packet_in, 21, match)
                      
            else: #all other cases -> switch to switch
                #send to f1s1
                if(header.dstip == '128.114.1.101' or header.dstip == '128.114.1.102'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 22, match)
                #send to f1s2
                elif(header.dstip == '128.114.1.103' or header.dstip == '128.114.1.104'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 23, match)
                #send to f2s1
                elif(header.dstip == '128.114.2.201' or header.dstip == '128.114.2.202'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 24, match)
                #send to f2s2
                elif(header.dstip == '128.114.2.203' or header.dstip == '128.114.2.204'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 25, match)
                #send to dcs
                elif(header.dstip == '128.114.3.178'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 26, match)
                #send to trusted host
                elif(header.dstip == '192.47.38.109'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 20, match)
                #send to untrusted host
                elif(header.dstip == '108.35.24.113'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 21, match)
        else:
            #flood all non-ip traffic
            packet_out = of.ofp_packet_out()
            packet_out.data = packet_in
            packet_out.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            self.connection.send(packet_out)
    else:
        #handle other switches
        if(packet.find('ipv4') or packet.find('icmp')):
            #handle ip traffic on other switches
            header = packet.find('ipv4')
            
            #floor 1 switch 1 - hosts 101, 102
            if(switch_id == '0000000000000002'):
                if(header.dstip == '128.114.1.101'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.1.101')
                    self.send_packet_format(packet_in, 1, match)
                elif(header.dstip == '128.114.1.102'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.1.102')
                    self.send_packet_format(packet_in, 2, match)
                else:
                    #send to core
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 20, match)
                    
            #floor 1 switch 2 - hosts 103, 104
            elif(switch_id == '0000000000000003'):
                if(header.dstip == '128.114.1.103'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.1.103')
                    self.send_packet_format(packet_in, 1, match)
                elif(header.dstip == '128.114.1.104'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.1.104')
                    self.send_packet_format(packet_in, 2, match)
                else:
                    #send to core
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 20, match)
                    
            #floor 2 switch 1 - hosts 201, 202
            elif(switch_id == '0000000000000004'):
                if(header.dstip == '128.114.2.201'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.2.201')
                    self.send_packet_format(packet_in, 1, match)
                elif(header.dstip == '128.114.2.202'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.2.202')
                    self.send_packet_format(packet_in, 2, match)
                else:
                    #send to core
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 20, match)
                    
            #floor 2 switch 2 - hosts 203, 204
            elif(switch_id == '0000000000000005'):
                if(header.dstip == '128.114.2.203'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.2.203')
                    self.send_packet_format(packet_in, 1, match)
                elif(header.dstip == '128.114.2.204'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.2.204')
                    self.send_packet_format(packet_in, 2, match)
                else:
                    #send to core
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 20, match)
                    
            #data center switch - server
            elif(switch_id == '0000000000000006'):
                if(header.dstip == '128.114.3.178'):
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = '128.114.3.178')
                    self.send_packet_format(packet_in, 1, match)
                else:
                    #send to core
                    match = of.ofp_match(dl_type = 0x0800, nw_dst = header.dstip)
                    self.send_packet_format(packet_in, 20, match)
        else:
            #flood non-ip traffic only
            packet_out = of.ofp_packet_out()
            packet_out.data = packet_in
            packet_out.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            self.connection.send(packet_out)
    return
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
