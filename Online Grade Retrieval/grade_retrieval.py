
import socket
import argparse
import sys
import time
from cryptography.fernet import Fernet

class Server:
 
    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    FILE_NAME = "course_grades_2024.csv"
    
    csv_dict = {}
    csv_header_map = {
            "Name" : 0,
            "ID Number" : 1,
            "Key" : 2,
            "Lab 1" : 3,
            "Lab 2" : 4,
            "Lab 3" : 5,
            "Lab 4" : 6,
            "Midterm" : 7,
            "Exam 1" : 8,
            "Exam 2" : 9,
            "Exam 3" : 10,
            "Exam 4" : 11

            }
    # for look up the column name based on its index. 
    inverse_csv_map = dict((x, y) for y, x in csv_header_map.items())

    user_found = False

    def __init__(self):
        self.read_csv_file()
        self.create_listen_socket()
        self.process_connections_forever()

    # Server 1
    def read_csv_file(self):
        #Open up file
        f = open(Server.FILE_NAME, 'r')
        firstline = 1
        print("Data read from CSV file: ")
        for line in f.readlines():
            print(line)
            if firstline:
                for header in line.split(','):
                    self.csv_dict[header.strip()] = []
            else:
                for i,entry in enumerate(line.split(',')):
                    self.csv_dict[self.inverse_csv_map[i]].append(entry.strip())
            firstline = 0
        # print(self.csv_dict)
        f.close()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )

            ############################################################
            # Set the (listen) socket to non-blocking mode.
            self.socket.setblocking(False)
            ############################################################            

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
            
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            ############################################################
            # Keep a list of the current client connections.
            self.connected_clients = []
            ############################################################

            # The main loop that we execute forever.
            while True:
                self.check_for_new_connections()
                self.service_connected_clients()

                # Periodically output the current number of connections.
                # print("{} ".format(len(self.connected_clients)), end="\r")
                sys.stdout.flush()
                time.sleep(0.1) 

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)
                
    def check_for_new_connections(self):                
        try:
            # Check if a new connection is available.
            new_client = self.socket.accept()
            new_connection, new_address_port = new_client

            # Announce that a new connection has been accepted.
            print("\nConnection received from {}.".format(new_address_port))

            # Set the new socket to non-blocking. 
            new_connection.setblocking(False)

            # Add the new connection to our connected_clients
            # list.
            self.connected_clients.append(new_client)
            
        except socket.error:
            # If an exception occurs, there are no new
            # connections. Continue on.
            pass

    # This function takein the recived str and process it
    def split_command(self, recvd_str):
        '''
        Args:
            recvd_str (str) : student number followed by command (see readme) exp. 400132290GL1A
        Retrun:
            id_bytes (str) : a string of student id in bytes
            command_bytes (str) : a string of command in bytes
            confirmation_byte (str) : a string of message to send to user in bytes
            user_found (bool) 
        '''
        command_bytes   = recvd_str.encode(Server.MSG_ENCODING)[7:]
        id_bytes        = recvd_str.encode(Server.MSG_ENCODING)[:7]
        id_str = id_bytes.decode(Server.MSG_ENCODING)
        welcome_bytes = b""

        #Loop through csv dictionary item to see if student number exists if it does, populates welcome bytes with their info
        if id_str in self.csv_dict["ID Number"]:
            welcome_bytes = (("Hello "+self.csv_dict["Name"][self.csv_dict["ID Number"].index(id_str)]+"!").encode(Server.MSG_ENCODING))
            self.user_found = True
            self.student_idx = self.csv_dict["ID Number"].index(id_bytes.decode(Server.MSG_ENCODING))
            print("User found.")
        #If the student number doesnt exist, populate welcome bytes with a failure message
        else:
            welcome_bytes = (f"Failed to find user with ID {id_str}.".encode(Server.MSG_ENCODING))
            print("User not found.")
        
        return (id_bytes, command_bytes, welcome_bytes)



    # calculate the averages of a col in the CSV 
    def get_avg_from_str(self, col):
        '''
        Arg:
            col (str) : column name from cmd
        Return:
            avg (float) : average
        '''
        avg = 0
        for grade in self.csv_dict[col]:
            avg += int(grade)
        avg /= len(self.csv_dict[col])
        return float(avg)


    def service_connected_clients(self):

        # Iterate through the list of connected clients, servicing
        # them one by one. Since we may delete from the list, make a
        # copy of it first.
        current_client_list = self.connected_clients.copy()

        for client in current_client_list:
            connection, address_port = client
            try:
                # Check for available incoming data.
                recvd_bytes = connection.recv(Server.RECV_SIZE)

                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                print("Received: ", recvd_str)
                # Check if the client has said "bye" or if the client
                # has closed the connection.
                if recvd_str == "bye" or len(recvd_str) == 0:
                    print()
                    print("Closing {} connection ...".format(address_port))
                    self.connected_clients.remove(client)
                    connection.close()
                    continue
                # Echo back what we received.
                connection.sendall(recvd_bytes)
                #print("\nEcho: Command entered: ", recvd_str)

                self.user_found = False

                # process the string
                (id_bytes, command_bytes, confirmation_bytes) =  self.split_command(recvd_str)
                sent_str = ""
                response_bytes = b""
                delimiter_bytes = b"Response:"

                

                # can't find user
                if not self.user_found:
                    sent_bytes = confirmation_bytes
                    connection.sendall(sent_bytes)
                    sent_str = sent_bytes.decode(Server.MSG_ENCODING)
                    print()
                    print("Closing {} connection ...".format(address_port))
                    self.connected_clients.remove(client)
                    try:
                        connection.close()
                    except Exception as e:
                        print("Connection was already closed")
                    finally:
                        continue

                # if we can find user, process command
                else:
                    print(f"Received {command_bytes.decode(Server.MSG_ENCODING)} command from client.")
                    # decipher the command
                    match command_bytes.decode(Server.MSG_ENCODING):
                        case "GMA":
                            type_ = "Midterm"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL1A":
                            type_ = "Lab 1"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL2A":
                            type_ = "Lab 2"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL3A":
                            type_ = "Lab 3"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GL4A":
                            type_ = "Lab 4"
                            avg = self.get_avg_from_str(type_)
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GEA":
                            type_ = "Exam"
                            avg = self.get_avg_from_str(type_ + " 1") + self.get_avg_from_str(type_ + " 2") + self.get_avg_from_str(type_ + " 3") + self.get_avg_from_str(type_ + " 4")
                            avg /= 4
                            response_bytes = f"The {type_} average was {avg}".encode(Server.MSG_ENCODING)
                        case "GG":
                            non_grade_data = ["Name", "ID Number", "Key"]
                            grades_str = ""
                            for key in self.csv_dict.keys():
                                if not key in non_grade_data:
                                    grade = self.csv_dict[key][self.student_idx]
                                    grades_str += f"\t{key}: {grade}\n"
                            response_bytes = f"Grades Found:\n{grades_str}".encode(Server.MSG_ENCODING)


                        case _:
                            response_bytes = b"Invalid Command!"

                    sent_bytes = confirmation_bytes + delimiter_bytes + response_bytes

                    fernet = Fernet(self.csv_dict["Key"][self.student_idx].encode('utf-8'))
                    connection.sendall(fernet.encrypt(sent_bytes))
                    sent_str = sent_bytes.decode(Server.MSG_ENCODING)
                    # print(sent_bytes)
                print("Sent: ", sent_str)




            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass

class Client:

    # Set the server to connect to. If the server and client are running
    # on the same machine, we can use the current hostname.
    # SERVER_HOSTNAME = socket.gethostname()
    # SERVER_HOSTNAME = "192.168.1.22"
    SERVER_HOSTNAME = socket.gethostbyname(socket.gethostname()) #Get ip address of current machine
    # SERVER_HOSTNAME = "localhost"
    
    # Try connecting to the compeng4dn4 echo server. You need to change
    # the destination port to 50007 in the connect function below.
    # SERVER_HOSTNAME = 'compeng4dn4.mooo.com'

    RECV_BUFFER_SIZE = 1024 # Used for recv.    
    # RECV_BUFFER_SIZE = 5 # Used for recv.    
    STUDENT_ID = ""
    SECRET_KEY = ""

    recieved_str = "" 

    def __init__(self):
        # self.get_socket()
        # self.connect_to_server()
        # self.send_console_input_forever()
        self.get_student_id_and_key()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow us to bind to the same port right away.            
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the client socket to a particular address/port.
            # self.socket.bind((Server.HOSTNAME, 40000))
                
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
            print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    # def get_console_input(self):
    #     # In this version we keep prompting the user until a non-blank
    #     # line is entered, i.e., ignore blank lines.
    #     while True:
    #         self.get_student_id_and_key()
    #         self.get_command()
    #         if self.input_text != "":
    #             break
    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_command()
                #Reconnect to server
                self.get_socket()
                self.connect_to_server()
                #Send the message + check response
                self.connection_send()
                self.connection_receive()
                #Close connection
                # print("Closing server connection ...")
                # self.socket.close()
                #get next ID + Key
                self.get_student_id_and_key()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                # If we get and error or keyboard interrupt, make sure
                # that we close the socket.
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall((self.STUDENT_ID+self.input_text).encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    #Ask user to input desired student ID 
    def get_student_id_and_key(self):
        print('*'*20)
        self.STUDENT_ID = ""
        self.SECRET_KEY = ""
        # self.STUDENT_ID = "1803933"
        # self.SECRET_KEY = "M7E8erO15CIh902P8DQsHxKbOADTgEPGHdiY0MplTuY="

        #Input Student Number
        while(self.STUDENT_ID == ""):
            self.STUDENT_ID = input("Enter your student id:\n")
        #Input secret key
        while(self.SECRET_KEY == ""):
            self.SECRET_KEY = input("Enter your secret key:\n")
        # error handling
        try:
            self.fernet = Fernet(self.SECRET_KEY.encode('utf-8'))
        except:
            print("Invalid key was entered. Please restart client application and try again.")
            sys.exit(1)


    #Get user to input the command 
    def get_command(self):
        valid_command = False
        #Loops until vaild command is entered
        while(not valid_command):
            # self.input_text = input("Enter a command:\n")
            self.input_text = input("Enter a command:\n") ### change this for testing
            print("Command entered: " + self.input_text)
            valid_command = True
            #Take user input and see if it matches any of the following commands
            match self.input_text:
                case "GMA":
                    type_ = "Midterm"
                    print(f"Fetching {type_} average")
                case "GL1A":
                    type_ = "Lab 1"
                    print(f"Fetching {type_} average")
                case "GL2A":
                    type_ = "Lab 2"
                    print(f"Fetching {type_} average")
                case "GL3A":
                    type_ = "Lab 3"
                    print(f"Fetching {type_} average")
                case "GL4A":
                    type_ = "Lab 4"
                    print(f"Fetching {type_} average")
                case "GEA":
                    type_ = "Exam"
                    print(f"Fetching {type_} average")
                case "GG":
                    print("Getting Grades")
                case _:
                    print("Invalid Command. Try Again.")
                    valid_command = False

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
            # print(f"recived bytes: {recvd_bytes}")

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            # print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))
                
            # ***important*** in serverside, error message are not encrypted
            # if unencrypted, there should be a error message with the word "Failed" in it
            # find() method is a string method that is used to find the index of a substring within a string. 
            # If the substring is not found, it returns -1.
            if recvd_bytes.decode(Server.MSG_ENCODING).find("Failed to find user with ID") == -1: # if true, the message is encrypted
                try:
                    decoded_bytes = self.fernet.decrypt(recvd_bytes)
                except Exception as e:
                    print(e)
                    decoded_bytes = recvd_bytes
                    print("Failed to decode message! (Invalid key?)")
            else:
                decoded_bytes = recvd_bytes

            # this is the string all in one piece
            recieved_str = decoded_bytes.decode(Server.MSG_ENCODING)
            # split at middle
            messages = recieved_str.split("Response:")
            # print(f"recived str: {recieved_str}")
            for message in messages:
                if messages.index(message) == 0:
                    print("Message: ", message)
                else:
                    print("Data: ", message)

            # turn this on when testing 
            # exit(1)

        except Exception as msg:
            print(msg)
            sys.exit(1)


if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()