#!/usr/bin/env python3

########################################################################
#
# Simple File Request/Download Protocol
#
########################################################################
#
# When the client connects to the server and wants to request a file
# download, it sends the following message: 1-byte GET command + 1-byte
# filename size field + requested filename, e.g.,

# ------------------------------------------------------------------
# | 1 byte GET command  | 1 byte filename size | ... file name ... |
# ------------------------------------------------------------------

# The server checks for the GET and then transmits the requested file.
# The file transfer data from the server is prepended by an 8 byte
# file size field as follows:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# The server needs to have REMOTE_FILE_NAME defined as a text file
# that the client can request. The client will store the downloaded
# file using the filename LOCAL_FILE_NAME. This is so that you can run
# a server and client from the same directory without overwriting
# files.

########################################################################

import socket
import argparse
import time
import os
import json
import threading
import argparse
import sys
import shutil

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN = 1  # 1 byte file name size field.
FILESIZE_FIELD_LEN = 8  # 8 byte file size field.

# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.

CMD = {"GET": 2, "LIST": 1, "PUT": 3,"BYE":4}
MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 150


########################################################################
# recv_bytes frontend to recv
########################################################################

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0  # total received bytes
        recv_bytes = b''  # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target - byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return (False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')


def read_filelist(path):
    filelist = []
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            filelist.append(file)
    return filelist


########################################################################
# SERVER
########################################################################

class Server:
    HOSTNAME = "127.0.0.1"

    PORT = 50000
    RECV_SIZE = 1024
    BACKLOG = 5
    Filepath = r"C:\Users\zhang\Documents\DN\File_transfer\server"
    temp_Filepath = r"C:\Users\zhang\Documents\DN\File_transfer\temp"
    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"
    MESSAGE =  "Chris, Mike and Dylan's FileSharing Service " + HOSTNAME
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    HOST = "0.0.0.0"
    # HOST = "192.168.1.255"
    # HOST = "255.255.255.255"
    ADDRESS_PORT = (HOST, PORT)

    def delete_files_in_folder(self, folder_path):
        try:
            # Iterate over all files in the folder
            for filename in os.listdir(folder_path):
                file_path = os.path.join(folder_path, filename)
                if os.path.isfile(file_path):
                    # Delete the file
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
        except Exception as e:
            print(f"An error occurred: {e}")

    def __init__(self):
        self.delete_files_in_folder(self.temp_Filepath)
        self.get_socket()
        self.create_listen_socket()
        print(f"server dir file list : {read_filelist(self.Filepath)}")
        self.process_connections_forever()

    def get_socket(self):
        try:
            # Create an IPv4 UDP socket.
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Set socket layer socket options.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to all interfaces and the agreed on broadcast port.
            self.udp_socket.bind(Server.ADDRESS_PORT)

            print("Listening for service discovery messages on SDP port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            exit(1)

    def receive_forever(self):

        while True:
            try:
                data, address = self.udp_socket.recvfrom(Server.RECV_SIZE)
                print("Broadcast received: ",
                      data.decode('utf-8'), address)
                self.udp_socket.sendto(Server.MESSAGE_ENCODED, address)
            except KeyboardInterrupt:
                print()
                exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

    def create_listen_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.ADDRESS_PORT)
            self.socket.listen(Server.BACKLOG)
            print("Listening for file sharing discovery on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        threading.Thread(target=self.receive_forever).start()
        try:
            while True:
                client=self.socket.accept()
                threading.Thread(target=self.connection_handler, args=(client,)).start()
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))
        while True:


            ################################################################
            # Process a connection and see if the client wants a file that
            # we have.

            # Read the command and see if it is a GET command.

            while True:
                status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
                if status:

                    break
                else:


                    time.sleep(0.5)

            cmd = int.from_bytes(cmd_field, byteorder='big')
            # Give up if we don't get a GET command.
            if cmd not in [CMD["GET"], CMD["LIST"], CMD["PUT"]]:
                print("Correct command not received. Closing connection ...")
                connection.close()
                break
            elif cmd == CMD["GET"]:
                # GET command is good. Read the filename size (bytes).
                status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)

                filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
                if not filename_size_bytes:
                    print("Connection is closed!")
                    connection.close()
                    break

                print('Filename size (bytes) = ', filename_size_bytes)

                # Now read and decode the requested filename.
                status, filename_bytes = recv_bytes(connection, filename_size_bytes)

                if not filename_bytes:
                    print("Connection is closed!")
                    connection.close()
                    break

                filename = filename_bytes.decode(MSG_ENCODING)
                print('Requested filename = ', filename)

                ################################################################
                # See if we can open the requested file. If so, send it.

                # If we can't find the requested file, shutdown the connection
                # and wait for someone else.
                try:
                    full_path = os.path.join(self.Filepath, filename)
                    with open(full_path, 'rb') as file:
                        filedata = file.read()
                except FileNotFoundError:
                    print(Server.FILE_NOT_FOUND_MSG)
                    print("file doesn't exist")

                    filedata="file doesn't exist".encode('utf-8')

                # Encode the file contents into bytes, record its size and
                # generate the file size field used for transmission.
                file_bytes = filedata
                file_size_bytes = len(file_bytes)
                file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

                # Create the packet to be sent with the header field.
                pkt = file_size_field + file_bytes

                try:
                    # Send the packet to the connected client.
                    connection.sendall(pkt)
                    print("Sending file: ", filename)
                    print("file size field: ", file_size_field.hex(), "\n")
                    # time.sleep(20)
                except socket.error:
                    # If the client has closed the connection, close the
                    # socket on this end.
                    print("Closing client connection ...")

                    connection.close()
                    break
                finally:
                        print("finish sending file")
            elif cmd == CMD["LIST"]:
                # GET command is good. Read the filename size (bytes).
                file_list = read_filelist(self.Filepath)

                print('file list: = ', file_list)

                # Now read and decode the requested filename.

                # Encode the file contents into bytes, record its size and
                # generate the file size field used for transmission.
                file_list_string = "\n".join(file_list)
                file_bytes = file_list_string.encode(MSG_ENCODING)

                try:
                    # Send the packet to the connected client.
                    connection.sendall(file_bytes)
                    print("Sending list")

                    # time.sleep(20)
                except socket.error:
                    # If the client has closed the connection, close the
                    # socket on this end.
                    print("Closing client connection ...")
                    connection.close()
                    break
                finally:
                    print("finish list")
            elif cmd == CMD["PUT"]:
                # GET command is good. Read the filename size (bytes).
                status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)

                filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
                if not filename_size_bytes:
                    print("Connection is closed!")
                    connection.close()
                    break

                print('Filename size (bytes) = ', filename_size_bytes)

                # Now read and decode the requested filename.
                status, filename_bytes = recv_bytes(connection, filename_size_bytes)

                if not filename_bytes:
                    print("Connection is closed!")
                    connection.close()
                    break
                filename = filename_bytes.decode(MSG_ENCODING)
                print('Requested filename = ', filename)

                status, filesize_field = recv_bytes(connection, FILESIZE_FIELD_LEN)
                filesize_bytes = int.from_bytes(filesize_field, byteorder='big')
                if not filesize_bytes:
                    print("Connection is closed!")
                    connection.close()
                    return
                if not status:
                    print("Closing connection ...")
                    connection.close()
                    return

                status, filedata_bytes = recv_bytes(connection, filesize_bytes)

                if not filedata_bytes:
                    print("Connection is closed!")
                    connection.close()
                    return

                try:
                    full_path = os.path.join(self.temp_Filepath, filename)
                    with open(full_path, 'wb') as file:
                        file.write(filedata_bytes)
                    shutil.copy2(full_path, self.Filepath)
                    # Delete the temporary file
                    os.remove(full_path)
                    print("file save success")
                    # time.sleep(20)
                

                except socket.error:
                    # If the client has closed the connection, close the
                    # socket on this end.
                    print("error happen on saving data")
                    print("Closing client connection ...")
                    connection.close()
                    return
                finally:
                    print("finish download")

            elif cmd==CMD["BYE"]:
                connection.close()

                return


########################################################################
# CLIENT
########################################################################

class Client:
    HOSTNAME = socket.gethostname()

    # Send the broadcast packet periodically. Set the period
    # (seconds).

    # Define the message to broadcast.
    MSG_ENCODING = "utf-8"
    MESSAGE = "Hello from " + HOSTNAME
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    # Use the broadcast-to-everyone IP address or a directed broadcast
    # address. Define a broadcast port.
    BROADCAST_ADDRESS = "255.255.255.255"  # or
    # BROADCAST_ADDRESS = "192.168.1.255"
    BROADCAST_PORT = 50000
    ADDRESS_PORT = (BROADCAST_ADDRESS, BROADCAST_PORT)
    Filepath = r"C:\Users\zhang\Documents\DN\File_transfer\client"
    RECV_SIZE = 10
    RECV_BUFFER_SIZE = 1024
    address=ADDRESS_PORT
    # Define the local file name where the downloaded file will be
    # saved.
    DOWNLOADED_FILE_NAME = "filedownload.txt"

    def __init__(self):
        self.create_sender_socket()

        self.get_socket()
        self.print_cmd()
        self.send_console_input_forever()

    def get_console_input(self, content):
        # In this version we keep prompting the user until a non-blank
        # line is entered, i.e., ignore blank lines.
        while True:
            input_text = input("{}: ".format(content))
            if input_text != "":
                break

        print("User entered: {}".format(input_text))

        return input_text

    def create_sender_socket(self):
        try:
            # Set up a UDP socket.
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Set socket layer socket options.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            ############################################################
            # Set the option for broadcasting.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            ############################################################
            self.udp_socket.settimeout(3)
            ############################################################
            # In more complex situations you may have to bind to an
            # interface.  This is to ensure that broadcasts are sent out
            # the correct interface, e.g.,
            # self.socket.bind(("192.168.1.22", 33333))

            # self.socket.bind(("127.0.0.1", 33333))
            ############################################################

        except Exception as msg:
                print(msg)
                sys.exit(1)

    def send_broadcasts_forever(self):
        try:

            print("Sending to {} ...".format(Client.ADDRESS_PORT))
            self.udp_socket.sendto(Client.MESSAGE_ENCODED, Client.ADDRESS_PORT)
            data, self.address = self.udp_socket.recvfrom(Client.RECV_BUFFER_SIZE)
            print("data received:",data.decode(self.MSG_ENCODING))
            print("Server address find",self.address)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.udp_socket.close()
    def print_cmd(self):
        commands = ["Command list:","scan", "connect", "get", "rlist", "put", "llist", "bye"]

        for command in commands:
            print(command)

    def send_console_input_forever(self):
        while True:
            try:
                command = self.get_console_input("Please type command:")
                match command:
                    case "scan":
                        self.send_broadcasts_forever()
                    case "connect":
                        self.connect_to_server()
                    case "get":
                        self.get_file()
                    case "rlist":
                        self.list_server()
                    case "put":
                        self.send_file()
                    case "llist":
                        self.list_client()
                    case "bye":
                        cmd_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder='big')
                        self.socket.sendall(cmd_field)
                        self.socket.close()
                        sys.exit(1)
                    case _:
                        print("wrong command")
                        self.send_console_input_forever()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                # If we get and error or keyboard interrupt, make sure
                # that we close the socket.
                self.socket.close()
                self.get_socket()
                self.connect_to_server()
                self.send_console_input_forever()

    def get_socket(self):

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()

    def connect_to_server(self):
        try:
            address=self.get_console_input("address:")
            port=int(self.get_console_input("port:"))
            self.address=(address,port)
            self.socket.connect(self.address)
        except Exception as msg:
            print(msg)
            exit()

    def send_file(self):
        cmd_field = CMD["PUT"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        filename = self.get_console_input("Please type file name:")
        filename_field_bytes = filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        full_path = os.path.join(self.Filepath, filename)
        try:
            with open(full_path, 'rb') as file:
                file_byte = file.read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            self.socket.close()
            return

        file_size_field = len(file_byte).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')
        pkt = cmd_field + filename_size_field + filename_field_bytes + file_size_field + file_byte

        try:
            # Send the packet to the connected client.
            self.socket.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            self.socket.close()
            return
        finally:

            return

    def get_file(self):

        ################################################################
        # Generate a file transfer request to the server

        # Create the packet cmd field.
        cmd_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        filename = self.get_console_input("Please type file name:")
        filename_field_bytes = filename.encode(MSG_ENCODING)
        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())

        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server

        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(self.socket, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            self.socket.close()
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            self.socket.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print("File size = ", file_size)

        # self.socket.settimeout(4)
        status, recvd_bytes_total = recv_bytes(self.socket, file_size)
        if not status:
            print("Closing connection ...")
            self.socket.close()
            return
        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.
        try:
            # Create a file using the received filename and store the
            # data.
            full_path = os.path.join(self.Filepath, filename)
            try:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
            except UnicodeDecodeError:
                with open(full_path, 'wb') as file:
                    file.write(recvd_bytes_total)

            else:
                if recvd_file=="file doesn't exist":
                    print("file doesn't exist")
                    self.send_console_input_forever()
                else:
                    with open(full_path, 'w') as file:
                        file.write(recvd_file)

            print(" Creating file:",full_path)
        except KeyboardInterrupt:
            print()
            sys.exit(1)

    def list_server(self):
        cmd_field = CMD["LIST"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.

        # Create the packet.
        print("Use List command ")
        pkt = cmd_field

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server

        # Read the file size field returned by the server.
        recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
        if len(recvd_bytes) == 0:
            print("Closing server connection ... ")
            self.socket.close()

        decoded_message = recvd_bytes.decode(MSG_ENCODING)
        print("message received: \n" + decoded_message)

    def list_client(self):
        print('\n')
        for filename in os.listdir(self.Filepath):
            print(filename)


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






