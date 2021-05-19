#pragma once
#include "LoginHandler.h"
#include "TransactionHandler.h"
#include "DBHandler.h"
#include "croncpp/croncpp.h"

class UserHandler {
private:
	DBHandler* dat;
	seal::PublicKey public_key;
public:
	UserHandler(DBHandler* dat, seal::PublicKey public_key);
	Account* login(seal::SEALContext context);
	void printMenu();
	void handleTransaction(seal::SEALContext context, seal::EncryptionParameters params);
	void showBalance(seal::SEALContext context, seal::EncryptionParameters params);
	void refreshDebits(seal::SEALContext context);
	void debitsMenu(seal::SEALContext context, seal::EncryptionParameters params);
	void addDebit(seal::SEALContext context, seal::EncryptionParameters params);
	void removeDebit(seal::SEALContext context, seal::EncryptionParameters params);
	void viewDebits(seal::SEALContext context, seal::EncryptionParameters params);
	void processChoice(seal::SEALContext context, seal::EncryptionParameters params);
	Account* getLoggedIn();
	void printTransactions(Account* loggedIn, seal::SEALContext context, seal::EncryptionParameters params);
};