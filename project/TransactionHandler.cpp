#include "TransactionHandler.h"
#include <algorithm>
#include <stdio.h>

TransactionHandler::TransactionHandler(TransactionList* transactions, DebitList* debits) {
	this->transactions = transactions;
	this->debits = debits;
}

bool TransactionHandler::transaction(Account* from, Account* to, double amount, seal::SEALContext context, seal::EncryptionParameters params) {
	if (from->debit(amount, context, params)) {
		to->credit(amount, context);
		return true;
	}
	std::cout << "Unable to process this transaction. You do not have enough money." << std::endl;
	return false;
}

TransactionList* TransactionHandler::getTransactions() {
	return transactions;
}

// Will only terminate when the money runs out, or when explicitly cancelled.
bool TransactionHandler::directDebit(DirectDebit* dD, seal::SEALContext context, seal::EncryptionParameters params) {
	try
	{
			time_t next = cron::cron_next(dD->getRegularity(), dD->getTimeSet());
			if (transaction(dD->getFrom(), dD->getTo(), dD->getAmount(context, params), context, params)) {
				return true;
			}
			else {
				std::cout << "Insufficient balance in account. Unable to perform standing order." << std::endl;
				return false;
			}
	}
	catch (cron::bad_cronexpr const& ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	
}

std::set<DirectDebit*> TransactionHandler::getDebits()
{
	return debits->getDebits();
}

DebitList* TransactionHandler::getDebitList()
{
	return debits;
}

DirectDebit* TransactionHandler::getNextDebit()
{
	return debits->getNextDebit();
}

void TransactionHandler::setDebitList(DebitList* debs)
{
	this->debits = debs;
}

