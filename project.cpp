#include "Account.h"
#include "TransactionHandler.h"
#include "LoginHandler.h"
#include <chrono>
#include <thread>
using std::cout;
using std::endl;
using std::cin;
using std::string;


void printUserMenu() {
	cout << "1: Make a transfer." << endl << "2: Check balance." << endl << "3: Check transaction history." << endl << "4: Exit." << endl;
}

void processChoice(LoginHandler* log, TransactionHandler* han) {
	printUserMenu();
	string choice;
	getline(cin, choice);
	if (choice == "1") {
		cout << "Transfer TBC" << endl;
		processChoice(log, han);
	}
	else if (choice == "2") {
		han->getDetails(log->getLogged());
		processChoice(log, han);
	}
	else if (choice == "3") {
		//log->getLogged()->printTransactions();
		cout << "Transactions TBC" << endl;
		processChoice(log, han);
	}
	else if (choice == "4"){
		cout << "Thank you. Goodbye!" << endl;
		std::this_thread::sleep_for(std::chrono::seconds(2));
		system("CLS");
	}
	else {
		cout << "Invalid choice. Please try again." << endl;
		processChoice(log, han);
	}
}

int main()
{
	boost::rational<int>* BoEInterest = new boost::rational<int>(1,1000);
	Account* l = new Account("Liam", "Radley", BoEInterest,"1234");
	Account* a = new Account("Aaron", "Radley", BoEInterest, "1234");
	AccountList* accounts = new AccountList();
	accounts->addAccount(a);
	accounts->addAccount(l);
	TransactionHandler* han = new TransactionHandler(accounts);
	LoginHandler* log = new LoginHandler(accounts);
	while (true) {
		cout << "Welcome to the Bank of Radley." << endl;
		cout << "What account do you want to login?" << endl;
		cout << "a : Aaron" << endl;
		cout << "l : Liam" << endl;

		string choice;

		do {
			getline(cin, choice);
			if (choice == "l") {
				log->login(l);
			}
			else if (choice == "a") {
				log->login(a);
			}
			else {
				cout << "Invalid choice." << endl;
			}
		} while (choice != "l" && choice != "a");
		if (!log->isLoggedIn()) {
			continue;
		}
		else {
			cout << "What would you like to do?" << endl;
			processChoice(log, han);
		}
	}
}
