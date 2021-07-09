#include "TransactionHandler.h"
#include <algorithm>
#include <stdio.h>

TransactionHandler::TransactionHandler(TransactionList* transactions, DebitList* debits) {
	this->transactions = transactions;
	this->debits = debits;
}

bool TransactionHandler::transaction(Account* from, Account* to, seal::Ciphertext amount, seal::SEALContext context, seal::EncryptionParameters params) {
	from->debit(amount, context);
	to->credit(amount, context);
	return true;
}

TransactionList* TransactionHandler::getTransactions() {
	return transactions;
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

