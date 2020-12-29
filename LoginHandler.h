#pragma once
#include "AccountList.h"

class LoginHandler {
private:
	Account* loggedAccount;
	AccountList* accounts;

public:

	LoginHandler(AccountList* accounts);
	
	bool login(Account* toLogin);

	bool isLoggedIn();

	void logout();

	Account* getLogged();
};