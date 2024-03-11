
note : use echo_polling_multiclient.py for starter code

Server:
    
    1) Read a csv file.
        The server prints out the data read from the CSV file, 
            e.g., “Data read from CSV file: “, followed by each row of the file. ***
        The server must print output indicating that it is then listening on 
        the host computer for incoming connections on a particular TCP port.

    4) When the server receives the TCP connection, it should print output, e.g., “Connection
    received from <IP address> on port <port>.” ***

    5) The server should print out what it has received, e.g., “Received GL3A command from
    client.”.

    6) If an ID was sent and matches a database entry, the server outputs a confirmation message, e.g., “User found.” Otherwise, the server prints out an error message, e.g., “User
    not found.” and the server closes the connection. Otherwise, it encrypts and returns the
    requested information. The server outputs the encrypted message that is sent.


Client:
    Command: 
        The request from the client always consists of the student ID number (i.e., 7 bytes) followed by
        one of the following commands: 
            i.e., GMA, GL1A, GL2A, GL3A, GL4A, GEA and GG.
        GMA/GEA are “get midterm/exam average” and the others are “get lab average” commands,
        e.g., GL3A is “get lab 3 average”, and so on.
        The GG command means to “get grades” for the requesting student rather than class averages. 

    2) When a command is entered, the client echos what has been entered, e.g., “Command entered: <cmd>”. ***
    
    3) If the command entered is a “get average” command, then the client will output a
    message such as “Fetching Lab 1 average:”. If the command entered is “GG”, the
    client will output a message such as“Getting Grades:” ***

    7) The client will then retrieve the server response, decrypt and output it on the terminal
    window

Example:
    Server print: "Data read from csv file: ..."
                    "listening for connection on port <...>"
    