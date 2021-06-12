#pragma once
#include "Account.h"
#include <chrono>
#include <time.h>
#include <string>


class Transaction {
private:
	std::time_t timestamp;
	std::string transactionType;
	std::string amountAddress;
	Account* transactionOwner;
	Account* otherAccount;
	
public:
	Transaction(std::string amountAddress, Account* transactionOwner, Account* otherAccount, std::string transactionType, time_t const timestamp);

	std::string printTransaction();
	std::string getAmount();
};