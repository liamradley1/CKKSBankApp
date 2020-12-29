#include "Transaction.h"

Transaction::Transaction(rational<int> amount, Account* otherAccount, string transactionType) {
	this->amount = amount;
	this->otherAccount = otherAccount;
	//this->timestamp = time(nullptr);
	this->transactionType = transactionType;
}

void Transaction::printTransaction() {
	//std::cout << "Time:" << std::put_time(std::localtime(&timestamp), "%c %Z") << std::endl;
	std::cout << "Account transferred ";
	if (transactionType == "credit") {
		std::cout << "from: ";
	}
	else {
		std::cout << "to: ";
	}
	std::cout << otherAccount->getFirstName() << " " << otherAccount->getLastName() << std::endl;
	std::cout << "Amount: " << (char)156 << otherAccount->convertToDouble(amount) << std::endl;
}