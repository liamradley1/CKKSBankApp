#pragma once
#include "Account.h"
#include <iostream>
#include <string>
#include <croncpp/croncpp.h>
class DirectDebit {
private:
	int debitID;
	Account* accountFrom;
	Account* accountTo;
	std::string amountAddress;
	cron::cronexpr regularity;
	std::time_t timeSet;
public:
	DirectDebit(int debitId, Account* accountFrom, Account* accountTo, std::string amountAddress, cron::cronexpr regularity, std::time_t timeSet);
	int getId();
	Account* getFrom();
	Account* getTo();
	std::string getAmountAddress();
	cron::cronexpr getRegularity();
	std::time_t getTimeSet();
	void setNewTime(std::time_t newTime);
	std::string printDebitInfo();
};