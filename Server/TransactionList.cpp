#include "TransactionList.h"

TransactionList::TransactionList(){}

bool TransactionList::addTransaction(Transaction* toAdd) {
	for (int i = 0; i < transactions.size(); ++i) {
		if (transactions.at(i) == toAdd) {
			return false;
		}
	}
	transactions.push_back(toAdd);
	return true;
}

bool TransactionList::removeTransaction(Transaction* toRemove) {
	for (int i = 0; i < transactions.size(); ++i) {
		if (transactions.at(i) == toRemove) {
			transactions.erase(transactions.begin() + i);
			return true;
		}
	}
	return false;
}

std::vector<Transaction*> TransactionList::getTransactions() {
	return transactions;
}