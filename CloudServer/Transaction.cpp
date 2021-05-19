#include "Transaction.h"
#include <seal/seal.h>
#include <fstream>

Transaction::Transaction(std::string amountAddress, Account* transactionOwner, Account* otherAccount, std::string transactionType, std::time_t timestamp) {
	this->amountAddress= amountAddress;
	this->transactionOwner = transactionOwner;
	this->otherAccount = otherAccount;
	this->transactionType = transactionType;
	this->timestamp = timestamp;
}

void Transaction::printTransaction(seal::SEALContext context, seal::EncryptionParameters params) {
	std::cout << "_________________________________________" << std::endl;
	std::cout << "Time:" << asctime(localtime(&timestamp));
	std::cout << "Account transferred ";
	if (transactionType.compare("credit") == 0) {
		std::cout << "from: ";
	}
	else {
		std::cout << "to: ";
	}
	std::cout << otherAccount->getFirstName() << " " << otherAccount->getLastName() << std::endl;
	std::cout << "Amount: " << (char)156;
	std::ifstream input(amountAddress, std::ios::binary);
	seal::Ciphertext amountCipher;
	amountCipher.load(context, input);
	double amount = Account::round2Dp(transactionOwner->decrypt(context, amountCipher, params));
	std::cout << amount << std::endl;
	std::cout << "_________________________________________" << std::endl;
}
