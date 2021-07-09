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
