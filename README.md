# CKKSBankApp

Key files:

- Benchmarking.cpp: Used for testing speeds and times to failure of encryption algorithms on different transactions. Also tests for the benefits of relinearisation.
- Client.cpp: Main file for the client-side. Handles all communications from the client to the central server.
- CloudServer.cpp: Main file for the cloud server. Handles all communications from the central server and processes them accordingly. Usually by performing encrypted addition and subtraction.
- DebitServer.cpp: Main file for the debit server. Handles all direct debit business logic and actions.
- InterestServer.cpp: Main file for the interest server. Handles all interest accrual business logic and actions.
- Server.cpp: Main file for the central server. Handles all communications to and from the client, as well as to and from the cloud server. Also handles the authentication logic for transactions.
- Account.cpp: Class for account. Stores information about client in memory.
- DBHandler.cpp: Communicator class with the DBMS.

- For files relating to the central server, check the Server directory. Similar logic applies to find files for the debit server, interest server, cloud server, benchmarking and client.
- The project directory creates executable files, which have been moved to the Executables directory for convenience. The CentralServer directory inside Executables contains the Server, DebitServer and InterestServer executables.
- The configuration is currently set to run on a local machine. This is for demonstration purposes.
- If setting this demo up to run locally, you must create a MySQL database as per the BankDB SQL script. Some alterations may need to be made within the DBHandler class files to reflect the username and password for your system.