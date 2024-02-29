#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import datetime

########################################################################
# Service Discovery Server
#
# The server listens on a UDP socket. When a service discovery packet
# arrives, it returns a response with the name of the service.
# 
########################################################################

class Server:

    ALL_IF_ADDRESS = "0.0.0.0"
    SERVICE_SCAN_PORT = 30000
    ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_SCAN_PORT)

    MSG_ENCODING = "utf-8"    
    
    SCAN_CMD = "SCAN"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)
    
    MSG = "Todd's File Sharing Service"
    MSG_ENCODED = MSG.encode(MSG_ENCODING)

    RECV_SIZE = 1024
    BACKLOG = 10

    def __init__(self):
        self.create_socket()
        self.receive_forever()

    def create_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.ALL_IF_ADDRESS, Server.SERVICE_SCAN_PORT) )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                print(Server.MSG, "listening on port {} ...".format(Server.SERVICE_SCAN_PORT))
                recvd_bytes, address = self.socket.recvfrom(Server.RECV_SIZE)

                print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
            
                # Decode the received bytes back into strings.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                # Check if the received packet contains a service scan
                # command.
                if Server.SCAN_CMD in recvd_str:
                    # Send the service advertisement message back to
                    # the client.
                    self.socket.sendto(Server.MSG_ENCODED, address)
            except KeyboardInterrupt:
                print()
                sys.exit(1)

########################################################################
# Service Discovery Client
#
# In this version, the client broadcasts service discovery packets and
# receives server responses. After a broadcast, the client continues
# to receive responses until a socket timeout occurs, indicating that
# no more responses are available. This scan process is repeated a
# fixed number of times. The discovered services are then output.
# 
########################################################################

class Client:

    RECV_SIZE = 1024
    MSG_ENCODING = "utf-8"    

    BROADCAST_ADDRESS = "255.255.255.255"
    # BROADCAST_ADDRESS = "192.168.1.255"    
    SERVICE_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_PORT)

    SCAN_CYCLES = 3
    SCAN_TIMEOUT = 2

    SCAN_CMD = "SCAN"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)

    def __init__(self):
        self.get_socket()
        self.scan_for_service()

    def get_socket(self):
        try:
            # Service discovery done using UDP packets.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Permit reusing this socket address.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Arrange to send a broadcast service discovery packet.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Set the socket for a socket.timeout if a scanning recv
            # fails.
            self.socket.settimeout(Client.SCAN_TIMEOUT);
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def scan_for_service(self):
        # Collect our scan results in a list.
        scan_results = []

        # Repeat the scan procedure a preset number of times.
        for i in range(Client.SCAN_CYCLES):

            # Send a service discovery broadcast.
            print("Sending broadcast scan {}".format(i))            
            self.socket.sendto(Client.SCAN_CMD_ENCODED, Client.ADDRESS_PORT)
        
            while True:
                # Listen for service responses. So long as we keep
                # receiving responses, keep going. Timeout if none are
                # received and terminate the listening for this scan
                # cycle.
                try:
                    recvd_bytes, address = self.socket.recvfrom(Client.RECV_SIZE)
                    recvd_msg = recvd_bytes.decode(Client.MSG_ENCODING)

                    # Record only unique services that are found.
                    if (recvd_msg, address) not in scan_results:
                        scan_results.append((recvd_msg, address))
                        continue
                # If we timeout listening for a new response, we are
                # finished.
                except socket.timeout:
                    break

        # Output all of our scan results, if any.
        if scan_results:
            for result in scan_results:
                print(result)
        else:
            print("No services found.")
                
########################################################################
# Fire up a client/server if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='client or server role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()
                

########################################################################






