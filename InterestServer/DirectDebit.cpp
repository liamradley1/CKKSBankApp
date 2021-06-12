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

std::string DirectDebit::printDebitInfo()
{
	std::string details = "_________________________________________\n"+ (std::string)"Debit id: " + std::to_string(debitID) + (std::string)"\nAccount to: " + accountTo->getFirstName() + " " + accountTo->getLastName() + "\nNext time due to send: " + asctime(localtime(&timeSet)) + "Amount: " + (char)156;
	return details;
}
