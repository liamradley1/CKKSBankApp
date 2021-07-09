#include "DBHandler.h"
#include <croncpp/croncpp.h>
#include <string>
#include <fstream>
using namespace mysqlx;

// Class constructor
DBHandler::DBHandler(TransactionHandler* tran)
{
	this->tran = tran;
	this->schema = nullptr;
	this->session = nullptr;
	this->accounts = nullptr;
	this->transactions = nullptr;
	this->debits = nullptr;
}

// Logs transaction in database
bool DBHandler::logTransaction(Account* from, Account* to, time_t nowTime)
{
	session->startTransaction();
	try {
		std::string transactionAddressFrom = std::to_string(from->getId()) + "'" + std::to_string(to->getId()) + "'" + std::to_string(nowTime) + ".txt";
		std::string transactionAddressTo = std::to_string(to->getId()) + "'" + std::to_string(from->getId()) + "'" + std::to_string(nowTime) + ".txt";
		transactions->insert("transactionTime", "transactionType", "amount", "transactionOwnerID", "otherAccountID").values(nowTime, "debit", transactionAddressFrom, from->getId(), to->getId()).execute();
		transactions->insert("transactionTime", "transactionType", "amount", "transactionOwnerID", "otherAccountID").values(nowTime, "credit", transactionAddressTo, to->getId(), from->getId()).execute();
		session->commit();
		return true;
	}
	catch (const Error& e) {
		std::cout << "Error caught: " << e.what() << std::endl;
		session->rollback();
		return false;
	}
}

// Establishes connection with database
bool DBHandler::connectToDB()
{
	try {
		Session* session = new Session(mysqlx::SessionOption::USER, "root",
			mysqlx::SessionOption::PWD, "admin",
			mysqlx::SessionOption::HOST, "localhost",
			mysqlx::SessionOption::PORT, 33060,
			mysqlx::SessionOption::DB, "bankdb"
		);
		Schema* schema = new Schema(*session, "bankdb");
		this->schema = schema;
		this->session = session;
		this->accounts = new Table(*schema, "accounts");
		this->transactions = new Table(*schema, "transactions");
		this->debits = new Table(*schema, "direct_debits");
		return true;
	}
	catch (std::exception& e) {
		std::cout << "Error:" << std::endl;
		std::cout << e.what() << std::endl;
		return false;
	}
}

// Ends connection with database
bool DBHandler::endConnection() {
	try {
		if (session != nullptr && schema != nullptr) {
			session->close();
			schema = nullptr;
			session = nullptr;
			std::cout << "Connection closed." << std::endl;
			return true;
		}
		std::cout << "Connection already closed." << std::endl;
		return false;
	}
	catch (std::exception& e) {
		std::cout << "Error:" << std::endl;
		std::cout << e.what() << std::endl;
		return false;
	}
}

Schema* DBHandler::getSchema() {
	return schema;
}

Session* DBHandler::getSession() {
	return session;
}

Table* DBHandler::getAccounts() {
	return accounts;
}

// Gets list of accounts
std::vector<Account*> DBHandler::getAccounts(seal::SEALContext context) {
	RowResult accountNums = accounts->select("id").orderBy("id").execute();
	std::vector<Account*> accounts;
	if (accountNums.count() == 0) {
		std::cout << "No accounts exist." << std::endl;
	}
	else {
		for (Row row : accountNums) {
			int accountId = (int)row.get(0);
			Account* toAdd = getAccount(accountId, context);
			accounts.push_back(toAdd);
		}
	}
	return accounts;
}

Table* DBHandler::getTransactions() {
	return transactions;
}

// Gets list of transactions on an account
TransactionList* DBHandler::getTransactions(int accountId, seal::SEALContext context) {
	RowResult tra = transactions->select("*").where("transactionOwnerID=" + std::to_string(accountId)).orderBy("transactionTime").execute();
	if (tra.count() == 0) {
		std::cout << "No transactions have occurred on this account." << std::endl;
		return nullptr;
	}
	else {
		for (Row row : tra) {
			int otherAccountId = (int)row.get(5);
			Account* currentAccount = getAccount(accountId, context);
			Account* otherAccount = getAccount(otherAccountId, context);
			Transaction* temp = new Transaction((std::string)row.get(3), currentAccount, otherAccount, (std::string)row.get(2), (std::time_t)row.get(1));
			tran->getTransactions()->addTransaction(temp);
		}
		return tran->getTransactions();
	}
	return nullptr;
}


// Gets account by ID
Account* DBHandler::getAccount(int id, seal::SEALContext context) {
	RowResult acc = accounts->select("*").where("id=" + std::to_string(id)).execute();
	if (acc.count() == 1) {
		Row row = acc.fetchOne();
		std::string getBal = (std::string)row.get(3);
		std::string getKey = (std::string)row.get(4);
		Account* accountSearched = new Account((int)row.get(0), (std::string)row.get(1), (std::string)row.get(2), (double)row.get(5), (size_t)row.get(6), getBal, getKey, context);
		return accountSearched;
	}
	else return nullptr;
}

// Legacy code for working with direct debits
bool DBHandler::directDebit(DirectDebit* dD, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params)
{
	/*try {
		if (logAndHandleTransaction(dD->getFrom(), dD->getTo(), dD->getAmount(context, params), public_key, context, params)) {
			return true;
		}
		else {
			removeDebit(dD);
			_sleep(1000);
		}
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}*/
	return true;
}

// Adds direct debit to the database
bool DBHandler::addDebit(DirectDebit* d, std::string regString, seal::SEALContext context, seal::EncryptionParameters params)
{
	try {
		session->startTransaction();
		debits->insert("transactionOwnerID", "otherAccountID", "amount", "regularity", "timeSet").values(d->getFrom()->getId(), d->getTo()->getId(), d->getAmountAddress(), regString, d->getTimeSet()).execute();
		session->commit();
		return tran->getDebitList()->addDebit(d);
	}
	catch (Error& e) {
		std::cout << e.what() << std::endl;
		session->rollback();
		return false;
	}
}

// Gets list of direct debits from database
DebitList* DBHandler::queryDebits(seal::SEALContext context) {
	try {
		RowResult deb = debits->select("*").execute();
		DebitList* newList = new DebitList();
		if (deb.count() > 0) {
			for (Row r : deb) {
				time_t newTime;
				if ((time_t)r.get(5) < time(nullptr)) {
					time_t now = time(nullptr);
					time_t next = cron::cron_next(cron::make_cron((std::string)r.get(4)), now);
					newTime = cron::cron_next(cron::make_cron((std::string)r.get(4)), time(nullptr));
				}
				else {
					newTime = (time_t)r.get(5);
				}
				DirectDebit* d = new DirectDebit((int)r.get(0), getAccount((int)r.get(1), context), getAccount((int)r.get(2), context), (std::string)r.get(3), cron::make_cron((std::string)r.get(4)), newTime);
				newList->addDebit(d);
				updateDebits(d);
			}
			return newList;
		}
		else {
			return nullptr;
		}
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}
	return nullptr;
}

// Updates time set in the database for direct debit
void DBHandler::updateDebits(DirectDebit* d) {
	try {
		session->startTransaction();
		debits->update().set("timeSet", d->getTimeSet()).where("debitID = :id").bind("id", d->getId()).execute();
		session->commit();
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
		session->rollback();
	}
}


// Requeries direct debits
void DBHandler::refreshDebits(seal::SEALContext context) {
	DebitList* debs = queryDebits(context);
	if (debs != nullptr) {
		tran->setDebitList(debs);
	}
	else {
		tran->setDebitList(new DebitList());
	}
}

// Deletes direct debit by reference
void DBHandler::removeDebit(DirectDebit* d)
{
	try {
		session->startTransaction();
		debits->remove().where("debitID = :debitID").bind("debitID", d->getId()).execute();
		session->commit();
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
		session->rollback();
	}
}

// Deletes direct debit by ID
void DBHandler::removeDebit(int id) {
	try {
		session->startTransaction();
		debits->remove().where("debitID = :debitID").bind("debitID", id).execute();
		session->commit();
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
		session->rollback();
	}
}

// Adds interest accrual transaction to database
void DBHandler::addInterestTransaction(Account* account, seal::SEALContext context, seal::EncryptionParameters params, seal::PublicKey publicKey, time_t nowTime) {
	try {
		session->startTransaction();
		std::string outputAddress = std::to_string(1) + "'" + std::to_string(account->getId()) + "'" + std::to_string(nowTime) + ".txt";
		std::ofstream output(outputAddress, std::ios::binary);
		transactions->insert("transactionTime", "transactionType", "amount", "transactionOwnerID", "otherAccountID").values(nowTime, "Monthly interest", outputAddress, account->getId(), 1).execute();
		session->commit();
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
		session->rollback();
	}
}
