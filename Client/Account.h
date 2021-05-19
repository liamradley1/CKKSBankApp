#pragma once
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>
#include <iostream>
#include <seal/seal.h>
using std::vector;

class Account {
private:
	int id;
	std::string firstName;
	std::string lastName;
	std::string balanceAddress;
	seal::SecretKey key;
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

	double getOverdraft();
	
	/* Prints account details to the terminal, and rounds the overdraft and balance.*/
	void printDetails(seal::SEALContext context, seal::EncryptionParameters params);

	/* Checks to see if the account has enough money before beginning the transaction. If not, then false is returned.
	If true, then the amount will be deducted from the balance and true is returned.*/
	bool debit(double amount, seal::SEALContext context, seal::EncryptionParameters params);
	
	/* Credits the relevant account.*/
	void credit(double amount, seal::SEALContext context);
	
	double decrypt(seal::SEALContext context, seal::Ciphertext toDecrypt, seal::EncryptionParameters params);

	/* Checks to see if account has a positive balance, then accrues interest if this is the case.*/
	//void accrueInterest();

	void accrueInterest(seal::SEALContext context, seal::EncryptionParameters params, seal::PublicKey publicKey);

	std::string convertToHex(int num);
};