#pragma once
#include "Transaction.h"
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>
#include <boost/rational.hpp>

using boost::rational;
using std::vector;
using std::string;

class Account {
private:
	int id;
	string firstName;
	string lastName;
	rational<int> balance;
	rational<int> overdraft;
	rational<int>* interestRate;
	size_t pin;
	vector<Transaction*> transactions;


public:
	/* Stores the hashed value of the inserted pin to check against when verifying.*/
	Account(string firstName, string lastName, rational<int>* interestRate, string pin);

	~Account();

	size_t getHashedPin();

	string getFirstName();

	string getLastName();

	rational<int> getBalance();
	
	/* Converts a rational into a double for ease of reading.*/
	double convertToDouble(rational<int> amount);
	
	/* Prints account details to the terminal, and rounds the overdraft and balance to 2 decimal places.*/
	void printDetails();
	
	/* Checks to see if the account has enough money before beginning the transaction. If not, then false is returned.
	If true, then the amount will be deducted from the balance and true is returned.*/
	bool debit(rational<int> amount);
	
	/* Credits the relevant account.*/
	void credit(rational<int> amount);
	
	/* Checks to see if account has a positive balance, then accrues interest if this is the case.*/
	void accrueInterest();

	/* Prints all transactions associated with the account.*/
	void printTransactions();
};