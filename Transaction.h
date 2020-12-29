#pragma once
#include "Account.h"
#include <boost/rational.hpp>
#include <chrono>

using std::time_t;

class Transaction {
private:
	time_t timestamp;
	string transactionType;
	rational<int> amount;
	Account* otherAccount;
	
public:
	Transaction(rational<int> amount, Account* otherAccount, string transactionType);

	void printTransaction();
};