#pragma once
#include "AccountList.h"

class TransactionHandler {
private:
	AccountList* accounts;
public:
	TransactionHandler(AccountList* accounts);

	/* Automates the process of transferring from one account to another. 
	Returns true if the transaction is successful and false if not.*/
	bool transaction(Account* from, Account* to, rational<int> amount);

	void getDetails(Account* toCheck) {
		toCheck->printDetails();
	}

};