#include "Account.h"
#include "UserHandler.h"
#include "TransactionList.h"
#include "DebitList.h"
#include "TransactionHandler.h"
#include "DBHandler.h"
#include <seal/seal.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <locale>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#include <codecvt>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sstream>
#pragma comment(lib, "cpprest_2_10")

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;
using namespace std;
using namespace std;

TransactionList* transactions = new TransactionList();
DebitList* debits = new DebitList();
TransactionHandler* tran = new TransactionHandler(transactions, debits);
DBHandler* dat = new DBHandler(tran);
seal::EncryptionParameters* params = new seal::EncryptionParameters(seal::scheme_type::ckks);
seal::SEALContext* context = new seal::SEALContext(NULL);

wstring readCloudDNS() {
    ifstream inFile("cloudDNS.txt");
    string location;
    inFile >> location;
    return wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(location);
}

wstring cloudDNS = readCloudDNS();

void getAmount(wstring balAddress, seal::Ciphertext& ciphertext) {
    seal::Ciphertext ciphertext2;
    http_client client(cloudDNS + L":8081/balance");
    auto response = client.request(methods::GET, balAddress);
    auto buf = response.get().body().streambuf();
    string contents = "";
    while (!buf.is_eof()) {
        if (buf.getc().get() != -2) // Gets rid of weird requiring 'async required' bugs
            contents += buf.sbumpc();
    }
    ofstream outFile(balAddress, std::ios::binary);
    outFile << contents;
    outFile.close();
    ifstream inFile(balAddress, std::ios::binary | std::ios::beg);
    ciphertext2.load(*context, inFile);
    inFile.close();
    ciphertext = ciphertext2;
    std::remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
}

void loadCKKSParams(seal::EncryptionParameters& params) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
}

void runInterestSubroutine(DBHandler* dat) {
    std::string regString = "0 0 0 1 * *"; // set to run monthly
    regString = "0 * * * * *"; // set to run every minute for debug 
    cron::cronexpr monthly = cron::make_cron(regString);
    time_t now = time(nullptr);
    time_t nextExec = cron::cron_next(monthly, now);
    while (true) {
        now = time(nullptr);
        wcout << "Time now: " << now << endl;
        wcout << "Next execution: " << nextExec << endl;
        if (nextExec <= now) {
            cout << "Let's get cracking" << endl;
            std::vector<Account*> accounts = dat->getAccounts(*context);
            if (accounts.size() > 0) {
                for (Account* acc : accounts) {
                    if (acc->getId() == 1) {
                        continue;
                    }
                    cout << "We get a non-admin account" << endl;
                    string keyAddress = acc->getKeyAddress();
                    std::ifstream keyIn(keyAddress, std::ios::binary);
                    seal::SecretKey secret_key;
                    secret_key.load(*context, keyIn);
                    keyIn.close();
                    cout << "Read in key at " << keyAddress << endl;
                    seal::Evaluator eval(*context);
                    seal::Decryptor decryptor(*context, secret_key);
                    seal::CKKSEncoder encoder(*context);
                    string balAddress = acc->getBalanceAddress();
                    seal::Ciphertext balanceCipher;
                    wstring wBalAddress = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(balAddress);
                    wcout << "Requesting " << wBalAddress << endl;
                    getAmount(wBalAddress, balanceCipher);
                    cout << "Read in balance at " << balAddress << endl;
                    double interestRate = 0.01; // Hard-coded, not ideal but it is what it is
                    vector<double> res;
                    seal::Plaintext plaintext;
                    decryptor.decrypt(balanceCipher, plaintext);
                    encoder.decode(plaintext, res);
                    double amount = res[0];
                    cout << "Amount in account: " << amount << endl;
                    if (amount > 0.0) {
                        seal::Encryptor encryptor(*context, secret_key);
                        seal::Plaintext interestPlain;
                        seal::CKKSEncoder encoder(*context);
                        seal::Ciphertext interestCipher;
                        double interest = - amount * interestRate;
                        cout << "Interest to pay: " << interest << endl;
                        double scale = pow(2, 20);
                        encoder.encode(interest, scale, interestPlain);
                        encryptor.encrypt_symmetric(interestPlain, interestCipher);
                        time_t nowTime = time(nullptr);
                        cout << "Current time: " << nowTime << endl;
                        http_client transactionClient(cloudDNS + L":8081/transfer");
                        string outputAddress = std::to_string(1) + "'" + std::to_string(acc->getId()) + "'" + std::to_string(nowTime) + ".txt";
                        wstring wideAddress = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(outputAddress);
                        wstring from = L"admin.txt";
                        wstring to = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(acc->getBalanceAddress());
                        wstring toSend = to + L"," + from + L"," + wideAddress;
                        wcout << toSend << endl;
                        ofstream amountOut(outputAddress, std::ios::binary);
                        interestCipher.save(amountOut);
                        amountOut.close();
                        cout << "Amount saved to file" << endl;
                        auto f = file_stream<char>::open_istream(wideAddress, std::ios::binary).get();
                        auto response = transactionClient.request(methods::PUT, toSend, f.streambuf());
                        wcout << response.get().status_code() << endl;
                        dat->addInterestTransaction(acc, *context, *params, nowTime);
                        std::remove(outputAddress.c_str());
                        cout << "Successful transaction!" << endl;
                    }
                }
            }
        }
        _sleep(999);
        nextExec = cron::cron_next(monthly, now);
    }
}


int main()
{
    cout << "Let's go" << endl;
    try
    {
        loadCKKSParams(*params);
        cout << "Params loaded" << endl;
        do {
            seal::SEALContext con(*params);
            cout << "Context created " << endl;
            context = new seal::SEALContext(con);
            cout << "Context copied" << endl;
        } while (false);
        dat->connectToDB();
        cout << "DB Connected to" << endl;
        while (true) {
            runInterestSubroutine(dat);
        }
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
    delete transactions;
    delete debits;
    delete tran;
    delete dat;
    delete params;
    delete context;
}