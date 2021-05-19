#pragma once
#include "DirectDebit.h"
#include <set>

class DebitList {
private:
	std::set<DirectDebit*> debits;
public:
	DebitList();
	bool addDebit(DirectDebit* toAdd);
	bool removeDebit(DirectDebit* toRemove);
	std::set<DirectDebit*> getDebits();
	DirectDebit* getNextDebit();
	std::set<DirectDebit*> getNextDebits();
};