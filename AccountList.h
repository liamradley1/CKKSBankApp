#pragma once
#include <set>
#include "Account.h"
class AccountList {
private:
	std::set<Account*> accounts;
public:
	AccountList();
	bool addAccount(Account* toAdd);
	bool removeAccount(Account* toRemove);
};