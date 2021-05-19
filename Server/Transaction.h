#pragma once
#include "Account.h"

#include <chrono>
#include <time.h>


class Transaction {
private:
	std::time_t timestamp;
	std::string transactionType;
	std::string amountAddress;
	Account* transactionOwner;
	Account* otherAccount;
	
public:
	Transaction(std::string amountAddress, Account* transactionOwner, Account* otherAccount, std::string transactionType, time_t const timestamp);

	void printTransaction(seal::SEALContext context, seal::EncryptionParameters params);
};