#pragma once
#include "LoginHandler.h"
#include "TransactionHandler.h"

#include <mysqlx/xdevapi.h>

using mysqlx::Session;
using mysqlx::Schema;
using mysqlx::Table;

class DBHandler {
private:
	LoginHandler* log;
	TransactionHandler* tran;
	Session* session;
	Schema* schema;
	Table* accounts;
	Table* transactions;
	Table* debits;

public:
	DBHandler(LoginHandler* log, TransactionHandler* tran);

	bool logAndHandleTransaction(Account* from, Account* to, seal::Ciphertext amount, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params);

	bool connectToDB();

	bool endConnection();

	Schema* getSchema();

	Session* getSession();

	Table* getAccounts();

	std::vector<Account*> getAccounts(seal::SEALContext context);

	Table* getTransactions();

	TransactionList* getTransactions(int accountId, seal::SEALContext context);

	Account* getAccount(int id, seal::SEALContext context);

	void logout();

	LoginHandler* getLog();

	bool directDebit(DirectDebit* dD, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params);

	void refreshLogged(seal::SEALContext context);

	bool addDebit(DirectDebit* d, std::string regString, seal::SEALContext context, seal::EncryptionParameters params);

	DebitList* queryDebits(seal::SEALContext context);

	void updateDebits(DirectDebit* d);

	void refreshDebits(seal::SEALContext context);

	void removeDebit(DirectDebit* d);

	void addInterestTransaction(Account* account, seal::SEALContext context, seal::EncryptionParameters params, seal::PublicKey publicKey);
};