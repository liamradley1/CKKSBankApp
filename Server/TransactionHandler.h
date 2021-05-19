#pragma once
#include "TransactionList.h"
#include "DebitList.h"
#include <set>

class TransactionHandler {
private:
	TransactionList* transactions;
	DebitList* debits;

public:
	TransactionHandler(TransactionList* transactions, DebitList* debits);

	/* Automates the process of transferring from one account to another. 
	Returns true if the transaction is successful and false if not.*/
	bool transaction(Account* from, Account* to, seal::Ciphertext amount, seal::SEALContext context, seal::EncryptionParameters params);

	TransactionList* getTransactions();

	bool directDebit(DirectDebit* directDebit, seal::SEALContext context, seal::EncryptionParameters params);

	std::set<DirectDebit*> getDebits();
	
	DebitList* getDebitList();

	DirectDebit* getNextDebit();

	void setDebitList(DebitList* debs);
};