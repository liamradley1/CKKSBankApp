#include <string>
#include <ios>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <boost/timer/timer.hpp>
#include "croncpp/croncpp.h"
#include "Account.h"
#include "TransactionHandler.h"
#include <seal/seal.h>
#include "LoginHandler.h"
#include "UserHandler.h"
#include "DBHandler.h"
#include "DirectDebit.h"
#include "DebitList.h"
#include <WinSock2.h>
#include <iomanip>

using std::string;
using std::cin;
using std::cout;
using std::endl;
using std::to_string;
using namespace seal;


void processDebits(DBHandler* dat, TransactionHandler* tran, DirectDebit* d, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params) {
    if (!dat->directDebit(d, public_key, context, params)) {
        std::cout << "Not enough money to run this direct debit." << endl;
        std::cout << "Deleting this direct debit." << endl;
        tran->getDebitList()->removeDebit(d);
        delete(d);
    }
    else {
        d->setNewTime(cron::cron_next(d->getRegularity(), time(nullptr)));
    }
}

void runInterestSubroutine(DBHandler* dat, seal::SEALContext context, seal::EncryptionParameters params, seal::PublicKey publicKey) {
    std::string regString = "0 0 0 1 * *"; // set to run monthly
    cron::cronexpr monthly = cron::make_cron(regString);
    time_t now = time(nullptr);
    time_t nextExec = cron::cron_next(monthly, now);
    while (true) {
        now = time(nullptr);
        if (nextExec <= now) {
            std::vector<Account*> accounts = dat->getAccounts(context);
            if (accounts.size() > 0) {
                for (Account* acc : accounts) {
                    if (acc->getId() == 1) {
                        continue;
                    }
                    dat->addInterestTransaction(acc, context, params, publicKey);
                }
            }
            nextExec = cron::cron_next(monthly, now);
        }
        _sleep(991);
    }
}

void runDebitSubroutine(DBHandler* dat, TransactionHandler* tran, UserHandler* user, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params) {
    try {
        user->refreshDebits(context);
        if (tran->getDebits().size() == 0) {
        }
        else {
            for (DirectDebit* d : tran->getDebits()) {
                time_t now = time(nullptr);
                time_t nextExec = cron::cron_next(d->getRegularity(), d->getTimeSet());
                if (now == nextExec - 1) {
                    processDebits(dat, tran, d, public_key, context, params);
                }
            }
        }
        _sleep(997);
        runDebitSubroutine(dat, tran, user, public_key, context, params);
    }
    catch (std::exception& e) {
        cout << e.what() << endl;
    }
}

void runRest(UserHandler* user, seal::SEALContext context, seal::EncryptionParameters params) {
    while (true) {
        try {
            user->login(context);
            if (user->getLoggedIn() != nullptr) {
                user->processChoice(context, params);
            }
        }
        catch (std::exception& e) {
            std::cout << e.what() << std::endl;
        }
    }
}

void createAndSaveBFVParams() {
    size_t poly_modulus_degree = 2048;
    EncryptionParameters params(scheme_type::bfv);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(1'342'177'28);
    SEALContext context(params);
    KeyGenerator keygen(context);
    SecretKey secret_key;
    PublicKey public_key;
    secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);

    std::ofstream privFileOut("privateKey.pem", std::ios::binary);
    secret_key.save(privFileOut);
    cout << "Successfully saved private key." << endl;
    privFileOut.close();

    std::ofstream pubFileOut("publicKey.pem", std::ios::binary);
    public_key.save(pubFileOut);
    cout << "Successfully saved public key." << endl;
    pubFileOut.close();

    std::ofstream paramsFileOut("params.txt", std::ios::binary);
    params.save(paramsFileOut);
    cout << "Successfully saved parameters." << endl;
    paramsFileOut.close();
}
void createAndSaveCKKSParams() {
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    SecretKey secret_key;
    PublicKey public_key;
    SEALContext context(params);
    KeyGenerator keyGen(context);
    keyGen.create_public_key(public_key);
    secret_key = keyGen.secret_key();
    cout << context.parameter_error_message() << endl;
    
    std::ofstream privFileOut("privateKeyCKKS.pem", std::ios::binary);
    secret_key.save(privFileOut);
    cout << "Successfully saved private key." << endl;
    privFileOut.close();

    std::ofstream pubFileOut("publicKeyCKKS.pem", std::ios::binary);
    public_key.save(pubFileOut);
    cout << "Sucessfully saved public key." << endl;
    pubFileOut.close();

    std::ofstream paramsFileOut("paramsCKKS.txt", std::ios::binary);
    params.save(paramsFileOut);
    cout << "Successfully saved parameters." << endl;
    paramsFileOut.close();
}

void loadBFVParams(EncryptionParameters& params, PublicKey& public_key) {
    std::ifstream paramsFileIn("params.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
    cout << "Successfully loaded parameters." << endl;
    SEALContext context(params);
    cout << context.parameter_error_message() << endl;

    std::ifstream pubFileIn("publicKey.pem", std::ios::binary);
    public_key.load(context, pubFileIn);
    pubFileIn.close();
    cout << "Successfully loaded public key." << endl;
}

void loadCKKSParams(EncryptionParameters& params, PublicKey& public_key) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
    SEALContext context(params);
    context = *(new SEALContext(params));
    std::ifstream pubFileIn("publicKeyCKKS.pem", std::ios::binary);
    public_key.load(context, pubFileIn);
    pubFileIn.close();
}

// Legacy code: Allows for the conversion of an integer into hexadecimal format.
//string convertToHx(int num) {
//    char arr[100];
//    int i = 0;
//    bool neg = false;
//    if (num < 0) {
//        num = -num;
//        neg = true;
//    }
//    while (num != 0) {
//        int temp = 0;
//        temp = num % 16;
//        if (temp < 10) {
//            arr[i] = temp + 48;
//            ++i;
//        }
//        else {
//            arr[i] = temp + 55;
//            ++i;
//        }
//        num = num / 16;
//    }
//    if (neg) {
//        arr[i] = '-';
//        ++i;
//    }
//    string result;
//    for (int j = i - 1; j >= 0; --j)
//        result.operator+=((arr[j]));
//    return result;
//}

void resetBalance(std::string balanceAddress, seal::SEALContext context, seal::PublicKey public_key) {
    std::ofstream output(balanceAddress, std::ios::binary);
    seal::CKKSEncoder encoder(context);
    seal::Encryptor enc(context, public_key);
    seal::Plaintext p;
    seal::Ciphertext c;
    double scale = pow(2, 20);
    encoder.encode(1000, scale, p);
    enc.encrypt(p, c);
    c.save(output);
    output.close();
}

int main() {
    /*try {
    

        DebitList* debitList = new DebitList();
        TransactionList* transactions = new TransactionList();
        TransactionHandler* tran = new TransactionHandler(transactions, debitList);
        LoginHandler* log = new LoginHandler();
        DBHandler* dat = new DBHandler(log, tran);
        UserHandler* user = new UserHandler(dat, public_key);

        std::thread subroutine1(runDebitSubroutine, dat, tran, user, public_key, context, params);
        std::thread subroutine2(runInterestSubroutine, dat, context, params, public_key);
        runRest(user, context, params);
        subroutine2.join();
        subroutine1.join();

        return 0;
    }
    catch (std::exception& e) {
        cout << e.what() << endl;
        return 1;
    }*/
    try {
        EncryptionParameters params;
        PublicKey public_key;
        loadCKKSParams(params, public_key);
        SEALContext context(params);
        DebitList* debitList = new DebitList();
        TransactionList* transactions = new TransactionList();
        TransactionHandler* tran = new TransactionHandler(transactions, debitList);
        LoginHandler* log = new LoginHandler();
        DBHandler* dat = new DBHandler(log, tran);
        UserHandler* user = new UserHandler(dat, public_key);
        std::thread subroutine1(runDebitSubroutine, dat, tran, user, public_key, context, params);
        std::thread subroutine2(runInterestSubroutine, dat, context, params, public_key);
        runRest(user, context, params);
    }
    catch (std::exception& e) {
        cout << e.what() << endl;
        return 1;
    }
}