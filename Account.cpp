#include "Account.h"
using std::string;
using boost::rational;

Account::Account(string firstName, string lastName, rational<int>* interestRate, string pin) {
	this->firstName = firstName;
	this->lastName = lastName;
	this->balance.assign(0, 1);
	this->overdraft.assign(1000, 1);
	this->interestRate = interestRate;
	size_t hashedPin = std::hash < std::string>{}(pin);
	this->pin = hashedPin;
}

Account::~Account() {
}

size_t Account::getHashedPin() {
	return pin;
}

string Account::getFirstName() {
	return firstName;
}

string Account::getLastName() {
	return lastName;
}

rational<int> Account::getBalance() {
	return balance;
}

double Account::convertToDouble(rational<int> amount) {
	double balance = boost::rational_cast<double>(amount);
	return balance;
}

void Account::printDetails() {
	std::cout <<"Name: " << firstName << " " << lastName << ",\nBalance: " << std::fixed << std::setprecision(2) << convertToDouble(this->balance) << ",\nOverdraft: " << convertToDouble(this->overdraft) << std::endl;
}

bool Account::debit(rational<int> amount) {
	if (balance + overdraft >= amount) {
		balance -= amount;
		return true;
	}
	else {
		return false;
	}
}

void Account::credit(rational<int> amount) {
	balance += amount;
}

void Account::accrueInterest() {
	if (balance > 0) {
		balance *= (1 + *interestRate);
	}
}

void Account::printTransactions() {
	for (int i = 0; i < transactions.size(); ++i) {
		transactions[i]->printTransaction();
	}
}
