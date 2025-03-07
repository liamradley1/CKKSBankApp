#pragma once
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>
#include <iostream>
#include <seal/seal.h>

class Account {
private:
	int id;
	std::string firstName;
	std::string lastName;
	std::string balanceAddress;
	std::string keyAddress;
	double overdraft;
	size_t pin;
	double interestRate;

public:
	/* Stores the hashed value of the inserted pin to check against when verifying.*/

	Account(int id, std::string firstName, std::string lastName, double overdraft, size_t pin, std::string balanceAddress, std::string keyAddress, seal::SEALContext context);

	~Account();

	static double round2Dp(double amount);

	int getId();

	size_t getHashedPin();

	std::string getFirstName();

	std::string getLastName();

	double getBalance(seal::SEALContext context, seal::EncryptionParameters params);

	std::string getBalanceAddress();

	std::string getKeyAddress();

	void printDetails(seal::SEALContext context, seal::EncryptionParameters params);

	double getOverdraft();

	/* Checks to see if the account has enough money before beginning the transaction. If not, then false is returned.
	If true, then the amount will be deducted from the balance and true is returned.*/
	void debit(seal::Ciphertext amount, seal::SEALContext context);
	
	/* Credits the relevant account.*/
	void credit(seal::Ciphertext amount, seal::SEALContext context);

	std::string convertToHex(int num);
};