#include "LoginHandler.h"
#include <iostream>

using std::string;

LoginHandler::LoginHandler(AccountList* accounts) {
	this->accounts = accounts;
	this->loggedAccount = nullptr;
}

bool LoginHandler::login(Account* account) {
	std::cout << "Please enter your pin, " << account->getFirstName() << std::endl;
	for (int i = 1; i < 4; ++i) {
		if (i != 1) {
			std::cout << "Incorrect pin. Please try again." << std::endl;
			std::cout << "Attempt: " << i << " out of 3" << std::endl;
		}
		string attempt;
		std::cout << "Pin: " << std::flush;
		getline(std::cin, attempt);
		if (std::hash<std::string>{}(attempt) == account->getHashedPin()) {
			std::cout << "Welcome, " << account->getFirstName() << ". Logging in." << std::endl;
			this->loggedAccount = account;
			return true;
		}
	}
	std::cout << "Your account has been locked out. Please try again later." << std::endl;
	return false;
}

bool LoginHandler::isLoggedIn() {
	return loggedAccount != nullptr;
}

void LoginHandler::logout() {
	loggedAccount = nullptr;
}

Account* LoginHandler::getLogged() {
	return loggedAccount;
}