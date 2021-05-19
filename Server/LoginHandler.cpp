#include "LoginHandler.h"
#include <iostream>

using std::string;

LoginHandler::LoginHandler() {
	this->loggedAccount = nullptr;
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

void LoginHandler::setLogged(Account* account) {
		this->loggedAccount = account;
}