import socket
import argparse
import sys
import threading
import json
import struct


chats = {} #dictionary for chatrooms

class Server:

    HOSTNAME = "192.168.2.121" #socket.gethostname()
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.thread_list = []
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )
            self.socket.listen(Server.BACKLOG)
            print("Chat Room Directory Server listening on port {} ...".format(Server.PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self): #good
        try:
            while True:
                new_client = self.socket.accept()
                new_thread = threading.Thread(target=self.connection_handler, args=(new_client,))

                # Record the new thread.
                self.thread_list.append(new_thread)

                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            print("Closing server socket ...")
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        while True:
            recvd_bytes = connection.recv(Server.RECV_SIZE)
            if len(recvd_bytes) == 0:
                print("Closing {} client connection ... ".format(address_port))
                connection.close()
                break
                
            data = recvd_bytes.decode(Server.MSG_ENCODING)

            if data == 'getdir':
                    recvd_bytes = json.dumps(chats).encode(Server.MSG_ENCODING)
                    connection.sendall(recvd_bytes)
                    #print("Fetching Current Chat Room Directory")
                    #print(chats) #return CCRD. For each entry include chat room name, multicast IP addr and port
            
            elif data[0:8] == 'makeroom':
                    split = data.split()
                    multiIP = split[-2]
                    port2 = split[-1]
                    name = ' '.join(split[1:-2])

                    check = chats.get(name,'DNE') #Check that group name is unique
                    if check == 'DNE': #If group name does not exist, group may be made if ip/port is unique
                        flag = 0
                        for i in chats:
                            w = chats.get(i)
                            if (w[0] == multiIP and str(w[1]) == port2):
                                flag = 1
                                recvd_bytes = 'IP Address/Port in use, try again'
                                recvd_bytes = recvd_bytes.encode(Server.MSG_ENCODING)
                                connection.sendall(recvd_bytes)
                                break
                            else:
                                flag = 0
                    
                        if flag == 0:
                            chats[name] = (str(multiIP),int(port2)) #Create a chat room directory if multiIP and port is unique
                            recvd_bytes = 'Chat room created'
                            recvd_bytes = recvd_bytes.encode(Server.MSG_ENCODING)
                            connection.sendall(recvd_bytes)

                    else: #Group name already in use, room may not be made
                        recvd_bytes = 'Group name is already being used, try a different name'
                        recvd_bytes = recvd_bytes.encode(Server.MSG_ENCODING)
                        connection.sendall(recvd_bytes)

            elif data[0:10] == 'deleteroom':
                split = data.split()
                name = ' '.join(split[1:len(split)])
                chats.pop(name,'Group does not exist') #remove chat name from CRD
                recvd_bytes = 'Chat room was removed'
                recvd_bytes = recvd_bytes.encode(Server.MSG_ENCODING)
                connection.sendall(recvd_bytes)

            elif data[0:4] == "chat":
                split = data.split()
                addresses = chats.get(split[1])
                print(addresses)
                recvd_bytes = json.dumps(addresses).encode(Server.MSG_ENCODING)
                connection.sendall(recvd_bytes)
            else:
                pass
                
        # except KeyboardInterrupt:
        #     print(); exit()

        # except Exception as msg:
        #     print(msg)
        #     sys.exit(1)



class Client:

    SERVER_HOSTNAME = '192.168.2.121'
    chat_host = '192.168.2.125'
    connect_flag = 0 
    RECV_BUFFER_SIZE = 1024

    RECV_SIZE = 256
    MSG_ENCODING = "utf-8"

    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    header = 'monkey: '

    def __init__(self):
        self.thread_list = []
        self.get_socket()
        # self.connect_to_server()
        self.send_console_input_forever()
        

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            self.input_text = input("Input: ")
            if self.input_text != "":
                break

    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()

                if self.input_text == "connect" and Client.connect_flag == 0:
                    Client.connect_flag = 1
                    self.connect_to_server()

                elif self.input_text == "getdir" and Client.connect_flag ==1 :
                    self.connection_send()
                    self.connection_receive()
                    

                elif self.input_text[0:8] == "makeroom" and Client.connect_flag ==1 :
                    splitted = self.input_text.split()
                    self.connection_send()
                    self.connection_receive() 
                    
                
                elif self.input_text[0:10] == "deleteroom" and Client.connect_flag ==1 :
                    splitted = self.input_text.split()
                    self.connection_send()
                    self.connection_receive()

                elif self.input_text == "bye" and Client.connect_flag ==1 : #good
                    raise KeyboardInterrupt

                elif self.input_text[0:4] == "name" and Client.connect_flag ==1 :
                    splitted = self.input_text.split()
                    Client.header = splitted[1] + ": "
                    

                elif self.input_text[0:4] == "chat" and Client.connect_flag ==1 :
                    splitted = self.input_text.split()
                    # print(splitted[0], splitted[1])
                    self.connection_send()
                    recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
                    recvd_bytes = recvd_bytes.decode(Server.MSG_ENCODING)
                    chat_address = json.loads(recvd_bytes)
                    chat_address = (chat_address[0], chat_address[1])
                    # chat_address = ('0.0.0.0', chat_address[1])
                    self.create_listen_socket(chat_address, chat_address[0], Client.chat_host)
                    self.create_send_socket()
                    print("-" * 72)
                    print("-" * 72)
                    print("Entering the chatroom", splitted[1])
                    self.chat_process_connections_forever(chat_address)


                else:
                    print("Command Does Not Exist or TCP connection has not yet established.")

            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing client socket ...")
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print(recvd_bytes.decode(Server.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def create_send_socket(self):
        try:
            self.snd_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.snd_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def create_listen_socket(self, BIND_ADDRESS_PORT, MULTICAST_ADDRESS, RX_IFACE_ADDRESS):
        try:
            self.lsn_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.lsn_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            self.lsn_socket.bind(BIND_ADDRESS_PORT)
                        
            multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)

            print("Multicast Group: ", MULTICAST_ADDRESS)

            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            multicast_request = multicast_group_bytes + multicast_if_bytes

            print("Adding membership (address/interface): ", MULTICAST_ADDRESS,"/", RX_IFACE_ADDRESS)
            self.lsn_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def chat_process_connections_forever(self, MULTICAST_ADDRESS_PORT):
        snd_thread = threading.Thread(target=self.send_chat_input_forever, args=(MULTICAST_ADDRESS_PORT,))
        self.thread_list.append(snd_thread)
        # snd_thread.daemon = True
        snd_thread.start()
        # lsn_thread = threading.Thread(target=self.receive_forever)
        # self.thread_list.append(lsn_thread)
        # # lsn_thread.daemon = True
        # lsn_thread.start()
        self.receive_forever()

    def send_chat_input_forever(self, MULTICAST_ADDRESS_PORT):
        while True:
            try:
                self.get_console_input2()

                if self.input_text[-9:] == "byebyebye": #
                    MESSAGE_ENCODED = self.input_text.encode(Client.MSG_ENCODING)
                    self.snd_socket.sendto(MESSAGE_ENCODED, MULTICAST_ADDRESS_PORT)
                    break

                self.input_text = Client.header + self.input_text
                MESSAGE_ENCODED = self.input_text.encode(Client.MSG_ENCODING)
                self.snd_socket.sendto(MESSAGE_ENCODED, MULTICAST_ADDRESS_PORT)

            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing client socket ...")
                self.snd_socket.close()
                sys.exit(1)

    def get_console_input2(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            self.input_text = input()
            if self.input_text != "":
                break

    def receive_forever(self):
        while True:
            try:
                data, address_port = self.lsn_socket.recvfrom(Client.RECV_SIZE)
                address, port = address_port
                # print("Received: ", data.decode('utf-8'), " Address:", address, " Port: ", port)
                msgs = data.decode(Client.MSG_ENCODING)
                if msgs[-9:] == "byebyebye":
                    break
                print(msgs)
                #add if statements per commands
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

    

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################





