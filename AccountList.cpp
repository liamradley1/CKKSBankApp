#include "AccountList.h"

AccountList::AccountList()
{
}

bool AccountList::addAccount(Account* toAdd) {
	if (accounts.find(toAdd) != accounts.end()) {
		return false;
	}
	accounts.insert(toAdd);
	return true;
}

bool AccountList::removeAccount(Account* toRemove) {
	if (accounts.find(toRemove) != accounts.end()) {
		accounts.erase(toRemove);
		return true;
	}
	return false;
}

//Account* AccountList::getAccount(string id)