#include "Transaction.h"
#include <sstream>

Transaction::Transaction(std::string amountAddress, Account* transactionOwner, Account* otherAccount, std::string transactionType, std::time_t timestamp) {
	this->amountAddress= amountAddress;
	this->transactionOwner = transactionOwner;
	this->otherAccount = otherAccount;
	this->transactionType = transactionType;
	this->timestamp = timestamp;
}

std::string Transaction::printTransaction() {
	std::string type;
	if (transactionType.compare("debit") == 0) {
		type = "to: ";
	}
	else {
		type = "from: ";
	}
	char* time = (asctime(localtime(&timestamp)));
	std::string details = "_________________________________________\n" + (std::string)"Time: " + time + "\nAccount transferred " + type + otherAccount->getFirstName() + " " + otherAccount->getLastName() + "\nAmount: " + (char)156;
	return details;
}

std::string Transaction::getAmount() {
	return this->amountAddress;
}
