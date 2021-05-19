#include "DebitList.h"
DebitList::DebitList(){
}

bool DebitList::addDebit(DirectDebit* toAdd) {
	if (debits.find(toAdd) != debits.end()) {
		return false;
	}
	debits.insert(toAdd);
	return true;
}

bool DebitList::removeDebit(DirectDebit* toRemove) {
	if (debits.find(toRemove) != debits.end()) {
		debits.erase(toRemove);
		return true;
	}
	return false;
}

std::set<DirectDebit*> DebitList::getDebits() {
	return debits;
}

DirectDebit* DebitList::getNextDebit()
{
	if (debits.size() == 0) {
		return nullptr;
	}
	auto iterator = debits.begin();
	DirectDebit* next = *iterator;

	for (DirectDebit* d : debits) {
		if (d != nullptr) {
			cron::cronexpr nextTime = next->getRegularity();
			cron::cronexpr dTime = d->getRegularity();
			std::time_t nextStep = cron::cron_next(nextTime, time(nullptr));
			std::time_t dStep = cron::cron_next(dTime, time(nullptr));
			if (nextStep > dStep) {
				next = d;
			}
		}
		else {
			debits.erase(d);
			delete(d);
		}
	}
	return next;
}

std::set<DirectDebit*> DebitList::getNextDebits()
{
	std::set<DirectDebit*> deb;	
	DirectDebit* next = getNextDebit();
	deb.insert(next);
	for (DirectDebit* d : debits) {
		if (next != d) {
			time_t currentTime = time(nullptr);
			time_t nextTime = cron::cron_next(next->getRegularity(), currentTime);
			time_t dTime = cron::cron_next(d->getRegularity(), currentTime);
			if (nextTime == dTime) {
				deb.insert(d);
			}
		}
	}
	return deb;
}
