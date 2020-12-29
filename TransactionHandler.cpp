#include "TransactionHandler.h"
#include <algorithm>
using boost::rational;

TransactionHandler::TransactionHandler(AccountList* accounts) {
	this->accounts = accounts;
}

void printTransactionDetails(Account* from, Account* to, rational<int> amount) {
	std::cout << from->getFirstName() << " " << from->getLastName() << " sent " << to->getFirstName() << " " << to->getLastName() << " " << ((char) 156) << std::fixed << std::setprecision(2) << from->convertToDouble(amount) << "." << std::endl;
}

bool TransactionHandler::transaction(Account* from, Account* to, rational<int> amount) {
	if (from->debit(amount)) {
		to->credit(amount);
		printTransactionDetails(from, to, amount);
		return true;
	}
	return false;
}

void getDetails(Account* toCheck) {

}