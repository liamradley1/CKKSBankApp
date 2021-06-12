#include "TransactionList.h"

TransactionList::TransactionList(){}

bool TransactionList::addTransaction(Transaction* toAdd) {
	if (transactions.find(toAdd) != transactions.end()) {
		return false;
	}
	transactions.insert(toAdd);
	return true;
}

bool TransactionList::removeTransaction(Transaction* toRemove) {
	if (transactions.find(toRemove) != transactions.end()) {
		transactions.erase(toRemove);
		return true;
	}
	return false;
}

std::set<Transaction*> TransactionList::getTransactions() {
	return transactions;
}