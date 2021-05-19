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
	this->overdraft = overdraft;
	this->pin = pin;
	std::ifstream inFile(keyAddress, std::ios::binary);
	this->key.load(context, inFile);
	inFile.close();
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
		return decrypt(context, t, params);
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}
}

double Account::getOverdraft() {
	return overdraft;
}

void Account::printDetails(seal::SEALContext context, seal::EncryptionParameters params) {
	double balance = getBalance(context, params);
	std::cout << "ID: " << id << ",\n" << "Name: " << firstName << " " << lastName << ",\nBalance: " << (char)156 << round2Dp(balance) <<"," << std::endl;
	std::cout << "Overdraft: " << (char)156 << round2Dp(this->overdraft) << std::endl;
}


bool Account::debit(double amount, seal::SEALContext context, seal::EncryptionParameters params) {
	std::ifstream inFile(this->balanceAddress, std::ios::binary);
	seal::Ciphertext balance;
	seal::CKKSEncoder encoder(context);
	balance.load(context, inFile);
	inFile.close();
	double balanceDec = decrypt(context, balance, params);

	if (balanceDec + overdraft >= amount) {
		double scale = pow(2, 20);
		seal::Evaluator eval(context);
		seal::CKKSEncoder enc(context);
		seal::Plaintext p;
		enc.encode(amount, scale, p);
		eval.sub_plain_inplace(balance, p);
		std::ofstream outFile(this->balanceAddress, std::ios::binary);
		balance.save(outFile);
		outFile.close();
		return true;
	}
	else {
		std::cout << "Unable to process." << std::endl;
		return false;
	}
}

void Account::credit(double amount, seal::SEALContext context) {
	std::ifstream inFile(this->balanceAddress, std::ios::binary);
	seal::Ciphertext balance;
	balance.load(context, inFile);
	inFile.close();
	double scale = pow(2, 20);
	seal::Evaluator eval(context);
	seal::CKKSEncoder enc(context);
	seal::Plaintext p;
	enc.encode(amount, scale, p);
	eval.add_plain_inplace(balance, p);
	std::ofstream outFile(this->balanceAddress, std::ios::binary);
	balance.save(outFile);
	outFile.close();
}

double Account::decrypt(seal::SEALContext context, seal::Ciphertext toDecrypt, seal::EncryptionParameters params)
{
	seal::CKKSEncoder encoder(context);
	seal::Decryptor decryptor(context, this->key);
	seal::Plaintext plainText;
	decryptor.decrypt(toDecrypt, plainText);
	std::vector<double> result;
	encoder.decode(plainText, result);
	return result[0];
}

void Account::accrueInterest(seal::SEALContext context, seal::EncryptionParameters params, seal::PublicKey publicKey) {
	seal::Evaluator eval(context);
	seal::CKKSEncoder enc(context);
	seal::Plaintext p;
	seal::Ciphertext bal;
	seal::RelinKeys relinKey;
	seal::KeyGenerator keyGen(context, this->key);
	keyGen.create_relin_keys(relinKey);
	double scale = pow(2, 20);
	std::ifstream balInput(balanceAddress, std::ios::binary);
	bal.load(context, balInput);
	enc.encode(interestRate, scale, p);
	eval.multiply_plain_inplace(bal, p);
	eval.relinearize_inplace(bal, relinKey);
	std::ofstream balOutput(balanceAddress, std::ios::binary);
	bal.save(balOutput);
	std::cout << "Success!" << std::endl;
}

