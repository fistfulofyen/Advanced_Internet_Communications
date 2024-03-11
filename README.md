# Advanced_Internet_Communications

This Repo contain projects and code snippet for computer network communications projects that will focus on Internet design and operational principles.

## Projects

### Online Grade Retrieval Application

Develop a client/server network application that can be used by a course instructor to distribute grades. The code will be written in Python using the Berkeley/POSIX socket API. The server software would be run by the course instructor and is given access to a database of student grade records. The server is non-blocking to allow multiple client to connect at the same time. The client software would be run by a student and communicates with the server in order to retrieve their information. A client can also issue commands that will return grade averages for particular grade categories. The server encrypts the data sent so that only the requesting client can decrypt the server response.

### Online File Sharing Application

Develop client and server network applications that implement file sharing. The code will be written in Python 3 using the Berkeley/POSIX socket API. The server software is run on a file sharing server and manages a directory that contains files to be shared. The client software communicates with the server in order to upload, list and retrieve the shared files. The Python code implement packet broadcasting for service discovery and use execution concurrency so that the server can interact with a TCP client while scanning for discovery requests.

## License

Copyright (C) ~~our lord and savior~~ Dr. Terence D. Todd Hamilton, Ontario, CANADA,
Todd@mcmaster.ca

Happy simulating![]-(￣▽￣)~*
