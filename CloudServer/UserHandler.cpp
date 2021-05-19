//#include "UserHandler.h"
//#include <thread>
//#include <fstream>
//
//UserHandler::UserHandler(DBHandler* dat, seal::PublicKey public_key)
//{
//	this->public_key = public_key;
//	this->dat = dat;
//	if (!dat->connectToDB()) {
//		std::cout << "Connection to database failed!" << std::endl;
//		exit(1);
//	}
//	
//}
//
//Account* UserHandler::login(seal::SEALContext context) {
//	return dat->login(context);
//}
//
//void UserHandler::printMenu() {
//	std::cout << "1: Make a transfer." << std::endl << "2: Check balance." << std::endl << "3: Check transaction history." << std::endl << "4: Add or remove direct debits." << std::endl << "5: Exit." << std::endl;
//}
//
//void UserHandler::printTransactions(Account* loggedIn, seal::SEALContext context, seal::EncryptionParameters params) {
//	TransactionList* list = dat->getTransactions(loggedIn->getId(), context);
//	if (list != nullptr) {
//		for (Transaction* t : list->getTransactions()) {
//			t->printTransaction(context, params);
//			list->removeTransaction(t);
//		}
//	}
//}
//
//void UserHandler::handleTransaction(seal::SEALContext context, seal::EncryptionParameters params) {
//	try {
//		std::string idTo;
//		int intIdTo;
//		while (true) {
//			std::cout << "Enter the id of the account you want to transfer to." << std::flush << std::endl;
//			std::getline(std::cin, idTo);
//			intIdTo = stoi(idTo);
//			std::cout << std::flush;
//			Account* accountTo = dat->getAccount(intIdTo, context);
//			if (accountTo != nullptr && intIdTo != getLoggedIn()->getId()) {
//				break;
//			}
//			else {
//				std::cout << "Invalid choice. Please try again." << std::endl;
//			}
//		}
//		Account* accountTo = dat->getAccount(intIdTo, context);
//		double amount;
//		std::string amountString;
//		std::cout << "Enter the amount of money you wish to transfer: Give this all in pence." << std::endl;
//		std::cout << "Amount: " << std::flush;
//		std::getline(std::cin, amountString);
//		amount = stod(amountString);
//		dat->refreshLogged(context);
//		if (amount > 0) {
//			dat->logAndHandleTransaction(getLoggedIn(), accountTo, amount, public_key, context, params);
//		}
//		else {
//			std::cout << "Invalid entry. Please try again." << std::endl;
//		}
//	}
//	catch (std::exception& e) {
//		std::cout << "Something went wrong! Please try again." << std::endl;
//		std::cout << e.what() << std::endl;
//		handleTransaction(context, params);
//	}
//}
//
//void UserHandler::showBalance(seal::SEALContext context, seal::EncryptionParameters params) {
//	dat->refreshLogged(context);
//	getLoggedIn()->printDetails(context, params);
//}
//
//void UserHandler::refreshDebits(seal::SEALContext context) {
//	dat->refreshDebits(context);
//}
//
//void UserHandler::addDebit(seal::SEALContext context, seal::EncryptionParameters params) {
//	try {
//		std::string idTo;
//		int intIdTo;
//		while (true) {
//			std::cout << "Enter the id of the account you want to transfer to." << std::endl;
//			std::getline(std::cin, idTo);
//			intIdTo = stoi(idTo);
//			std::cout << std::flush;
//			Account* accountTo = dat->getAccount(intIdTo, context);
//			if (accountTo != nullptr && intIdTo != getLoggedIn()->getId()) {
//				break;
//			}
//			else {
//				std::cout << "Invalid choice. Please try again." << std::endl;
//			}
//		}
//		Account* accountTo = dat->getAccount(intIdTo, context);
//		std::string choice;
//		std::string regString;
//		while (true) {
//			std::cout << "Please enter the regularity of the payment:" << std::endl;
//			std::cout << "1: Once every second" << std::endl;
//			std::cout << "2: Once a minute" << std::endl;
//			std::cout << "3: Once an hour" << std::endl;
//			std::cout << "4: Once a day" << std::endl;
//			std::cout << "5: Once a week" << std::endl;
//			std::cout << "6: On the first of every month" << std::endl;
//			std::cout << "7: Once a year" << std::endl;
//			std::getline(std::cin, choice);
//			if (choice == "1") {
//				regString = "* * * * * ?";
//				break;
//			}
//			else if (choice == "2") {
//				regString = "0 * * * * ?";
//				break;
//			}
//			else if (choice == "3") {
//				regString = "0 0 * * * ?";
//				break;
//			}
//			else if (choice == "4") {
//				regString = "0 0 0 * * ?";
//				break;
//			}
//			else if (choice == "5") {
//				regString = "0 0 0 * * 1";
//				break;
//			}
//			else if (choice == "6") {
//				regString = "0 0 0 1 * *";
//				break;
//			}
//			else if (choice == "7") {
//				regString = "0 0 0 1 1 ?";
//				break;
//			}
//			else {
//				std::cout << "Invalid choice. Please try again." << std::endl;
//			}
//		}
//		cron::cronexpr reg = cron::make_cron(regString);
//		double amount = 0;
//		std::string amountString;
//		while (amount <= 0) {
//			std::cout << "Enter the amount of pounds you wish to transfer: " << std::endl;
//			std::cout << "Amount: " << (char)156 << std::flush;
//			getline(std::cin, amountString);
//			amount = stod(amountString);
//			if (amount <= 0) {
//				std::cout << "Invalid entry. Please try again." << std::endl;
//			}
//		}
//		dat->refreshLogged(context);
//		seal::Encryptor enc(context, public_key);
//		seal::CKKSEncoder encoder(context);
//		seal::Ciphertext c;
//		double scale = pow(2, 20);
//		seal::Plaintext p;
//		encoder.encode(amount, scale, p);
//		enc.encrypt(p, c);
//		std::string amountAddress = std::to_string(dat->getLog()->getLogged()->getId()) + "'" + std::to_string(accountTo->getId()) + "'" + std::to_string(time(nullptr));
//		std::ofstream output(amountAddress, std::ios::binary);
//		c.save(output);
//		DirectDebit* d = new DirectDebit(0, dat->getLog()->getLogged(), accountTo, amountAddress, reg, time(nullptr));
//		if (dat->addDebit(d, regString, context, params)) {
//			std::cout << "Direct debit added successfully!" << std::endl;
//			refreshDebits(context);
//		}
//		else {
//			std::cout << "Direct debit not added successfully! Please try again." << std::endl;
//		}
//	}
//	catch (std::exception& e) {
//		std::cout << "Something went wrong!" << std::endl;
//		std::cout << e.what() << std::endl;
//	}
//}
//
//void UserHandler::removeDebit(seal::SEALContext context, seal::EncryptionParameters params) {
//	if (dat->queryDebits(context) != nullptr) {
//		std::cout << "Type the id of the direct debit you wish to remove:" << std::endl;
//		viewDebits(context, params);
//		std::string choice;
//		std::getline(std::cin, choice);
//		for (DirectDebit* d : dat->queryDebits(context)->getDebits()) {
//			if (d->getFrom()->getId() == dat->getLog()->getLogged()->getId() && std::stoi(choice) == d->getId()) {
//				dat->removeDebit(d);
//			}
//		}
//	}
//	else {
//		std::cout << "You have no direct debits set up." << std::endl;
//	}
//}
//
//void UserHandler::viewDebits(seal::SEALContext context, seal::EncryptionParameters params) {
//	if (dat->queryDebits(context) != nullptr) {
//		int counter = 0;
//		for (DirectDebit* d : dat->queryDebits(context)->getDebits()) {
//			if (d->getFrom()->getId() == dat->getLog()->getLogged()->getId()) {
//				d->printDebitInfo(context, params);
//				++counter;
//			}
//		}
//		if(counter == 0) {
//			std::cout << "You have no direct debits set up." << std::endl;
//		}
//	}
//	else {
//		std::cout << "You have no direct debits set up." << std::endl;
//	}
//	
//}
//
//void UserHandler::debitsMenu(seal::SEALContext context, seal::EncryptionParameters params) {
//	std::cout << "What would you like to do?" << std::endl;
//	std::cout << "1: Add a direct debit." << std::endl;
//	std::cout << "2: Remove a direct debit." << std::endl;
//	std::cout << "3: View direct debits." << std::endl;
//	std::cout << "4: Exit this menu." << std::endl;
//	std::string choice;
//	getline(std::cin, choice);
//	if (choice == "1") {
//		addDebit(context, params);
//		debitsMenu(context, params);
//	}
//	else if (choice == "2") {
//		removeDebit(context, params);
//		debitsMenu(context, params);
//	}
//	else if (choice == "3") {
//		viewDebits(context, params);
//		debitsMenu(context, params);
//	}
//	else if (choice == "4") {
//		processChoice(context, params);
//	}
//	else {
//		std::cout << "Invalid choice. Please try again." << std::endl;
//		debitsMenu(context, params);
//	}
//}
//
//void UserHandler::processChoice(seal::SEALContext context, seal::EncryptionParameters params) {
//	printMenu();
//	std::string choice;
//	getline(std::cin, choice);
//	if (choice == "1") {
//		handleTransaction(context, params);
//		processChoice(context, params);
//	}
//	else if (choice == "2") {
//		showBalance(context, params);
//		processChoice(context, params);
//	}
//	else if (choice == "3") {
//		printTransactions(dat->getLog()->getLogged(), context, params);
//		processChoice(context, params);
//	}
//	else if (choice == "4") {
//		debitsMenu(context, params);
//	}
//	else if (choice == "5") {
//		std::cout << "Thank you. Goodbye!" << std::endl;
//		dat->logout();
//
//		std::this_thread::sleep_for(std::chrono::seconds(2));
//		system("CLS");
//	}
//	else {
//		std::cout << "Invalid choice. Please try again." << std::endl;
//		processChoice(context, params);
//	}
//}
//
//Account* UserHandler::getLoggedIn() {
//	return dat->getLog()->getLogged();
//}

