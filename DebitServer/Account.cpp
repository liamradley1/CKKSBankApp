#include "Account.h"
#include <fstream>
#include <iostream>
#include <string>
using std::string;

double Account::round2Dp(double amount) {
	double f, xi, xf;
	xf = modf(amount, &xi);
	f = floor(xf * 100 + 0.5) / 100.0;
	return xi + f;
}

Account::Account(int id, std::string firstName, std::string lastName, double overdraft, size_t pin, string balanceAddress, string keyAddress, seal::SEALContext context)
{
	this->id = id;
	this->firstName = firstName;
	this->lastName = lastName;
	this->balanceAddress = balanceAddress;
	this->keyAddress = keyAddress;
	this->overdraft = overdraft;
	this->pin = pin;
	this->interestRate = 0.05;
}

Account::~Account() {
}

string Account::convertToHex(int num) {
	char arr[100];
	int i = 0;
	bool neg = false;
	if (num < 0) {
		num = -num;
		neg = true;
	}
	while (num != 0) {
		int temp = 0;
		temp = num % 16;
		if (temp < 10) {
			arr[i] = temp + 48;
			++i;
		}
		else {
			arr[i] = temp + 55;
			++i;
		}
		num = num / 16;
	}
	if (neg) {
		arr[i] = '-';
		++i;
	}
	string result;
	for (int j = i - 1; j >= 0; --j)
		result.operator+=((arr[j]));
	return result;
}

int Account::getId() {
	return id;
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

double Account::getBalance(seal::SEALContext context, seal::EncryptionParameters params) {
	try {
		std::ifstream in(this->balanceAddress, std::ios::binary);
		seal::Ciphertext t;
		t.load(context, in);
		in.close();
		return 0.0;
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}
}

std::string Account::getBalanceAddress() {
	return this->balanceAddress;
}

double Account::getOverdraft() {
	return overdraft;
}

void Account::printDetails(seal::SEALContext context, seal::EncryptionParameters params) {
	double balance = getBalance(context, params);
	std::cout << "ID: " << id << ",\n" << "Name: " << firstName << " " << lastName << ",\nBalance: " << (char)156 << round2Dp(balance) <<"," << std::endl;
	std::cout << "Overdraft: " << (char)156 << round2Dp(this->overdraft) << std::endl;
}

std::string Account::getKeyAddress() {
	return this->keyAddress;
}


void Account::debit(seal::Ciphertext amount, seal::SEALContext context) {
	std::ifstream inFile(this->balanceAddress, std::ios::binary);
	seal::Ciphertext balance;
	seal::Evaluator evaluator(context);
	balance.load(context, inFile);
	inFile.close();
	evaluator.sub_inplace(balance, amount);
	std::ofstream outFile(this->balanceAddress, std::ios::binary);
	balance.save(outFile);
}

void Account::credit(seal::Ciphertext amount, seal::SEALContext context) {
	std::ifstream inFile(this->balanceAddress, std::ios::binary);
	seal::Ciphertext balance;
	balance.load(context, inFile);
	inFile.close();
	seal::Evaluator eval(context);
	eval.add_inplace(balance, amount);
	std::ofstream outFile(this->balanceAddress, std::ios::binary);
	balance.save(outFile);
	outFile.close();
}

