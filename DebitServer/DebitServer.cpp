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

static TransactionList* transactions = new TransactionList();
static DebitList* debits = new DebitList();
static TransactionHandler* tran = new TransactionHandler(transactions, debits);
static DBHandler* dat = new DBHandler(tran);
static seal::EncryptionParameters* params = new seal::EncryptionParameters(seal::scheme_type::ckks);
static seal::SEALContext* context = new seal::SEALContext(NULL);

// Reads in cloud DNS from file
wstring readCloudDNS() {
    ifstream inFile("cloudDNS.txt");
    string location;
    inFile >> location;
    return wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(location);
}

wstring cloudDNS = readCloudDNS();

// HTTP request for file. Receives file information and returns ciphertext
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

// Main workhorse program for processingt direct debits. Checks to see if debit is due and carries it out if it is. Deletes debit if not enough money present in account 
void processDebits(DBHandler* dat, TransactionHandler* tran) {
    try {
        while (true) {
            auto debitList = dat->queryDebits(*context);
            if (debitList == nullptr) {
                _sleep(999);
                continue;
            }
            set<DirectDebit*> debits = debitList->getDebits();
            for (DirectDebit* d : debits) {
                time_t nowTime = time(nullptr);
                wcout << "Next time to act: " << d->getTimeSet() << endl;
                wcout << "Time now: " << nowTime << endl;
                if (d->getTimeSet() <= nowTime) {
                    string keyAddress = d->getFrom()->getKeyAddress();
                    cout <<"Key address: " <<  keyAddress << endl;
                    std::ifstream keyIn(keyAddress, std::ios::binary);
                    seal::SecretKey secret_keyFrom;
                    seal::SecretKey secret_keyTo;
                    secret_keyFrom.load(*context, keyIn);
                    keyIn.close();
                    ifstream keyInTo(d->getTo()->getKeyAddress(), std::ios::binary);
                    secret_keyTo.load(*context, keyInTo);
                    keyInTo.close();
                    string address = d->getAmountAddress();
                    wstring toSend = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(address);
                    seal::Ciphertext ciphertext, fromBal, toBal;
                    getAmount(toSend, ciphertext);
                    seal::Decryptor decryptor(*context, secret_keyFrom);
                    seal::CKKSEncoder encoder(*context);
                    seal::Plaintext plaintext;
                    decryptor.decrypt(ciphertext, plaintext);
                    vector<double> res1, res2;
                    encoder.decode(plaintext, res1);
                    double amount = res1[0];
                    Account* from = d->getFrom();
                    Account* to = d->getTo();
                    string fromAddress = from->getBalanceAddress();
                    toSend = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(fromAddress);
                    getAmount(toSend, fromBal);
                    decryptor.decrypt(fromBal, plaintext);
                    encoder.decode(plaintext, res2);
                    double bal = res2[0];
                    cout << "Account balance: " << bal << endl;
                    cout << "Amount to send: " << amount << endl;
                    if (bal + from->getOverdraft() > amount) {
                        http_client client(cloudDNS + L":8081/transfer");
                        wstring wAddress = to_wstring(from->getId()) + L"'" + to_wstring(to->getId()) + L"'" + to_wstring(nowTime) + L".txt";
                        wcout << wAddress << endl;
                        std::ofstream outFile(address, std::ios::binary);
                        ciphertext.save(outFile);
                        outFile.close();
                        wstring toSendFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(from->getBalanceAddress()) + L"," + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(to->getBalanceAddress()) + L"," + wAddress;
                        auto f = file_stream<char>::open_istream(std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(address), std::ios::binary).get();
                        auto response = client.request(methods::PUT, toSendFile, f.streambuf());
                        wcout << response.get().status_code();
                        wAddress = to_wstring(to->getId()) + L"'" + to_wstring(from->getId()) + L"'" + to_wstring(nowTime) + L".txt";
                        toSendFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(to->getBalanceAddress()) + L"," + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(from->getBalanceAddress()) + L"," + wAddress;
                        amount = -amount;
                        double scale = pow(2, 20);
                        encoder.encode(amount, scale, plaintext);
                        seal::Encryptor encryptor(*context, secret_keyTo);
                        encryptor.encrypt_symmetric(plaintext, ciphertext);
                        ofstream outFile2(wAddress, std::ios::binary);
                        ciphertext.save(outFile2);
                        outFile2.close();
                        f = file_stream<char>().open_istream(wAddress, std::ios::binary).get();
                        response = client.request(methods::PUT, toSendFile, f.streambuf());
                        wcout << response.get().status_code() << endl;
                        if (response.get().status_code() == status_codes::OK) {
                            dat->logTransaction(from, to, nowTime);
                            cout << "Successful direct debit from " << from->getId() << " to " << to->getId() << " for amount " << (char)156 << -amount << "." << endl << endl;
                            _sleep(1000);
                        }
                    }
                    else {
                        std::wcout << "Deleting direct debit " << d->getId() << " as user " << from->getId() << " does not have the sufficient balance" << endl << endl;
                        dat->removeDebit(d->getId());
                    }
                    delete from;
                    delete to;
                }
                debitList->removeDebit(d);
            }
            _sleep(999);
        }
    }
    catch (exception& e) {
        std::wcout << e.what() << endl;
    }
}

// Load in CKKS parameters from file
void loadCKKSParams(seal::EncryptionParameters& params) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
}

int main()
{
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
            processDebits(dat, tran);
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
