#include "DirectDebit.h"
#include <fstream>

DirectDebit::DirectDebit(int debitID, Account* accountFrom, Account* accountTo, std::string amountAddress, cron::cronexpr regularity, std::time_t timeSet)
{
	this->debitID = debitID;
	this->accountFrom = accountFrom;
	this->accountTo = accountTo;
	this->amountAddress = amountAddress;
	this->regularity = regularity;
	this->timeSet = timeSet;
}

int DirectDebit::getId()
{
	return debitID;
}

Account* DirectDebit::getFrom()
{
	return accountFrom;
}

Account* DirectDebit::getTo()
{
	return accountTo;
}

std::string DirectDebit::getAmountAddress() {
	return amountAddress;
}

double DirectDebit::getAmount(seal::SEALContext context, seal::EncryptionParameters params)
{	
	std::ifstream input(amountAddress, std::ios::binary);
	seal::Ciphertext c;
	c.load(context, input);
	return accountFrom->decrypt(context, c, params);
}

cron::cronexpr DirectDebit::getRegularity()
{
	return regularity;
}

std::time_t DirectDebit::getTimeSet()
{
	return timeSet;
}

void DirectDebit::setNewTime(std::time_t newTime)
{
	this->timeSet = newTime;
}

void DirectDebit::printDebitInfo(seal::SEALContext context, seal::EncryptionParameters params)
{
	double amount = getAmount(context, params);
	std::cout << "Debit id: " << debitID << std::endl << "Account to: " << accountTo->getFirstName() << " " << accountTo->getLastName() << std::endl << "Amount: " << (char)156 << Account::round2Dp(amount);
	std::cout << std::endl << "Next time due to send: " << asctime(localtime(&timeSet)) << std::endl;
}
