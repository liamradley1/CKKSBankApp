#pragma once
#include "Transaction.h"
#include <set>

/* Provides temporary storage of a client's transactions if they wish to view them while in app.*/
class TransactionList {
private:
	std::set<Transaction*> transactions;

public:
	TransactionList();
	bool addTransaction(Transaction* toAdd);
	bool removeTransaction(Transaction* toRemove);
	std::set<Transaction*> getTransactions();
};