//#include <seal/seal.h>
//#include "TCPHandler.h"
//#include "UserHandler.h"
//#include "DBHandler.h"
//#include "LoginHandler.h"
//#include "TransactionHandler.h"
//#include "TransactionList.h"
//
//
//void processDebits(DBHandler* dat, TransactionHandler* tran, DirectDebit* d, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params) {
//    if (!dat->directDebit(d, public_key, context, params)) {
//        std::cout << "Not enough money to run this direct debit." << std::endl;
//        std::cout << "Deleting this direct debit." << std::endl;
//        tran->getDebitList()->removeDebit(d);
//        delete(d);
//    }
//    else {
//        d->setNewTime(cron::cron_next(d->getRegularity(), time(nullptr)));
//    }
//}
//
//void runInterestSubroutine(DBHandler* dat, seal::SEALContext context, seal::EncryptionParameters params, seal::PublicKey publicKey) {
//    std::string regString = "0 0 0 1 * *"; // set to run monthly
//    cron::cronexpr monthly = cron::make_cron(regString);
//    time_t now = time(nullptr);
//    time_t nextExec = cron::cron_next(monthly, now);
//    while (true) {
//        now = time(nullptr);
//        if (nextExec <= now) {
//            std::vector<Account*> accounts = dat->getAccounts(context);
//            if (accounts.size() > 0) {
//                for (Account* acc : accounts) {
//                    if (acc->getId() == 1) {
//                        continue;
//                    }
//                    dat->addInterestTransaction(acc, context, params, publicKey);
//                }
//            }
//            nextExec = cron::cron_next(monthly, now);
//        }
//        _sleep(991);
//    }
//}
//
////void runDebitSubroutine(DBHandler* dat, TransactionHandler* tran, UserHandler* user, seal::PublicKey public_key, seal::SEALContext context, seal::EncryptionParameters params) {
////    try {
////        user->refreshDebits(context);
////        if (tran->getDebits().size() == 0) {
////        }
////        else {
////            for (DirectDebit* d : tran->getDebits()) {
////                time_t now = time(nullptr);
////                time_t nextExec = cron::cron_next(d->getRegularity(), d->getTimeSet());
////                if (now == nextExec - 1) {
////                    processDebits(dat, tran, d, public_key, context, params);
////                }
////            }
////        }
////        _sleep(997);
////        runDebitSubroutine(dat, tran, user, public_key, context, params);
////    }
////    catch (std::exception& e) {
////        std::cout << e.what() << std::endl;
////    }
////}
//
//void createAndSaveBFVParams() {
//    size_t poly_modulus_degree = 2048;
//    seal::EncryptionParameters params(seal::scheme_type::bfv);
//    params.set_poly_modulus_degree(poly_modulus_degree);
//    params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
//    params.set_plain_modulus(1'342'177'28);
//    seal::SEALContext context(params);
//    seal::KeyGenerator keygen(context);
//    seal::SecretKey secret_key;
//    seal::PublicKey public_key;
//    secret_key = keygen.secret_key();
//    keygen.create_public_key(public_key);
//
//    std::ofstream privFileOut("privateKey.pem", std::ios::binary);
//    secret_key.save(privFileOut);
//    std::cout << "Successfully saved private key." << std::endl;
//    privFileOut.close();
//
//    std::ofstream pubFileOut("publicKey.pem", std::ios::binary);
//    public_key.save(pubFileOut);
//    std::cout << "Successfully saved public key." << std::endl;
//    pubFileOut.close();
//
//    std::ofstream paramsFileOut("params.txt", std::ios::binary);
//    params.save(paramsFileOut);
//    std::cout << "Successfully saved parameters." << std::endl;
//    paramsFileOut.close();
//}
//void createAndSaveCKKSParams() {
//    seal::EncryptionParameters params(seal::scheme_type::ckks);
//    size_t poly_modulus_degree = 8192;
//    params.set_poly_modulus_degree(poly_modulus_degree);
//    params.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
//    seal::SecretKey secret_key;
//    seal::PublicKey public_key;
//    seal::SEALContext context(params);
//    seal::KeyGenerator keyGen(context);
//    keyGen.create_public_key(public_key);
//    secret_key = keyGen.secret_key();
//    std::cout << context.parameter_error_message() << std::endl;
//    std::ofstream privFileOut("privateKeyCKKS.pem", std::ios::binary);
//    secret_key.save(privFileOut);
//    std::cout << "Successfully saved private key." << std::endl;
//    privFileOut.close();
//
//    std::ofstream pubFileOut("publicKeyCKKS.pem", std::ios::binary);
//    public_key.save(pubFileOut);
//    std::cout << "Sucessfully saved public key." << std::endl;
//    pubFileOut.close();
//
//    std::ofstream paramsFileOut("paramsCKKS.txt", std::ios::binary);
//    params.save(paramsFileOut);
//    std::cout << "Successfully saved parameters." << std::endl;
//    paramsFileOut.close();
//}
//
//void loadBFVParams(seal::EncryptionParameters& params, seal::PublicKey& public_key) {
//    std::ifstream paramsFileIn("params.txt", std::ios::binary);
//    params.load(paramsFileIn);
//    paramsFileIn.close();
//    std::cout << "Successfully loaded parameters." << std::endl;
//    seal::SEALContext context(params);
//    std::cout << context.parameter_error_message() << std::endl;
//
//    std::ifstream pubFileIn("publicKey.pem", std::ios::binary);
//    public_key.load(context, pubFileIn);
//    pubFileIn.close();
//    std::cout << "Successfully loaded public key." << std::endl;
//}
//
//
//
//Account* serverLoginSequence(LoginHandler* log, DBHandler* dat, seal::SEALContext context, TCPHandler handler, SOCKET &ClientSocket, SOCKET &ListenSocket, SOCKET &ConnectSocket) {
//    try {
//            dat->connectToDB();
//            int choice = handler.receiveInt(ClientSocket);
//            int received = 0;
//            if (choice == 0) {
//                std::cout << "Connected client app has been closed." << std::endl;
//                return nullptr;
//            }
//            std::cout << "Login attempt on " << choice << " received!" << std::endl;
//            Account* account = dat->getAccount(choice, context);
//            if (account != nullptr) {
//                handler.transmitInt(ConnectSocket, 1);
//            }
//            else {
//                handler.transmitInt(ConnectSocket, 0);
//                return nullptr;
//            }
//            std::cout << "Welcome, " << account->getFirstName() << std::endl;
//            int len = handler.receiveInt(ClientSocket);
//            char* pin = handler.receiveCharArray(ClientSocket, len);
//            std::cout << pin << std::endl;
//            if (std::to_string(account->getHashedPin()).compare(pin) == 0) {
//                std::cout << "Pin matches!" << std::endl;
//                handler.transmitInt(ConnectSocket, 1);
//                return account;
//            }
//            else {
//                std::cout << "Pin does not match!" << std::endl;
//                handler.transmitInt(ConnectSocket, 0);
//                return nullptr;
//            }
//            std::cout << "Ready for next request!" << std::endl;
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//    }
//}
//
//bool serverTransferSequence(DBHandler* dat, TCPHandler handler, SOCKET& ConnectSocket, SOCKET& ClientSocket, seal::SEALContext context, seal::PublicKey public_key, seal::EncryptionParameters params, Account* logged) {
//    // Receive account id
//    try {
//        int id = handler.receiveInt(ClientSocket);
//        Account* accTo = dat->getAccount(id, context);
//        if (accTo == nullptr) {
//            std::cout << "Invalid account." << std::endl;
//            handler.transmitInt(ConnectSocket, 1);
//            return false;
//        }
//        else {
//            std::cout << "Valid account." << std::endl;
//            handler.transmitInt(ConnectSocket, 0);
//            std::cout << "Receive file and name" << std::endl;
//            const char* name = handler.receiveFile(ClientSocket);
//            if (name == nullptr) {
//                handler.transmitInt(ClientSocket, 1);
//                return false;
//            }
//            std::cout << "File name: " << name << std::endl;
//            seal::Ciphertext c;
//            std::ifstream inFile(name, std::ios::binary);
//            c.load(context, inFile);
//            inFile.close();
//            std::cout << "Ciphertext extracted!" << std::endl;
//            dat->logAndHandleTransaction(logged, accTo, c, public_key, context, params);
//            handler.transmitInt(ConnectSocket, 0);
//            return true;
//        }
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//        handler.transmitInt(ClientSocket, 1);
//        return false;
//    }
//}
//
//bool serverBalanceSequence(TCPHandler handler, SOCKET &ConnectSocket, SOCKET &ClientSocket, seal::SEALContext context, Account* logged) {
//    handler.transmitFile(ConnectSocket, logged->getBalanceAddress());
//    int read = handler.receiveInt(ClientSocket);
//    std::cout << read << std::endl;
//    if (read == 1) {
//        std::cout << "Information not received properly. Trying again." << std::endl;
//        return serverBalanceSequence(handler, ConnectSocket, ClientSocket, context, logged);
//        
//    }
//    return true;
//}
//
//bool serverHistorySequence(TCPHandler handler, SOCKET& ConnectSocket, SOCKET& ClientSocket, seal::SEALContext context, seal::EncryptionParameters params, DBHandler* dat, Account* logged) {
//    try {
//        TransactionList* list = dat->getTransactions(logged->getId(), context);
//        if (list == nullptr) {
//            return true;
//        }
//        for (Transaction* t : list->getTransactions()) {
//            try {
//                while (true) {
//                    t->printTransaction(context, params);
//                    list->removeTransaction(t);
//                    break;
//                }
//            }
//            catch (std::exception& e) {
//                std::cout << e.what() << std::endl;
//            }
//        }
//        return true;
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//        return false;
//    }
//}
//
//bool serverMenuSequence(DBHandler* dat, TCPHandler handler, SOCKET &ConnectSocket, SOCKET& ClientSocket, seal::SEALContext context, seal::PublicKey public_key, seal::EncryptionParameters params, Account* logged) {
//    try {
//        while (true) {
//            int choice = handler.receiveInt(ClientSocket);
//            std::cout << "choice: " << choice << std::endl;
//            switch (choice) {
//            case 1:
//                serverTransferSequence(dat, handler, ConnectSocket, ClientSocket, context, public_key, params, logged);
//                break;
//            case 2:
//                serverBalanceSequence(handler, ConnectSocket, ClientSocket, context, logged);
//                break;
//            case 3:
//                serverHistorySequence(handler, ConnectSocket, ClientSocket, context, params, dat, logged);
//                std::cout << "Program is exited." << std::endl;
//                break;
//            case 4:
//                break;
//            case 5:
//                std::cout << "Logging out!" << std::endl;
//                dat->logout();
//                return true;
//            default:
//                std::cout << "Number greater than expected received!" << std::endl;
//                break;
//            }
//        }
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//    }
//}
//
//int __cdecl main(void)
//{
//    //try {
//    //    TCPHandler handler;
//    //    SOCKET ClientSocket;
//    //    SOCKET ListenSocket;
//    //    SOCKET ConnectSocket;
//    //    while (true) {
//    //        ClientSocket = INVALID_SOCKET;
//    //        ListenSocket = INVALID_SOCKET;
//    //        ConnectSocket = INVALID_SOCKET;
//    //        handler.initiateListenConnection(DEFAULT_RECEIVE_PORT, ClientSocket, ListenSocket);
//    //        handler.initiateSendConnection(DEFAULT_SEND_PORT, ConnectSocket);
//    //        seal::PublicKey public_key;
//    //        seal::EncryptionParameters params;
//    //        loadCKKSParams(params, public_key);
//    //        std::cout << params.coeff_modulus().size() << std::endl;
//    //        seal::SEALContext context(params);
//    //        DebitList* debits = new DebitList();
//    //        TransactionList* transactions = new TransactionList();
//    //        LoginHandler* log = new LoginHandler();
//    //        TransactionHandler* tran = new TransactionHandler(transactions, debits);
//    //        DBHandler* dat = new DBHandler(log, tran);
//    //        Account* logged = serverLoginSequence(log, dat, context, handler, ClientSocket, ListenSocket, ConnectSocket);
//    //        if (logged != nullptr) {
//    //            log->setLogged(logged);
//    //            std::cout << "Loading menu: " << std::endl;
//    //            serverMenuSequence(dat, handler, ConnectSocket, ClientSocket, context, public_key, params, logged);
//    //        }
//    //        closesocket(ClientSocket);
//    //        closesocket(ListenSocket);
//    //        closesocket(ConnectSocket);
//    //        WSACleanup();
//    //        delete dat;
//    //        delete tran;
//    //        delete log;
//    //        delete transactions;
//    //        delete debits;
//    //    }
//    //}
//    //catch (std::exception& e) {
//    //    std::cout << e.what() << std::endl;
//    //}
//
//

//
//    //std::ifstream inFile2("privateKeyCKKS.pem", std::ios::binary);
//    //std::ifstream inFile3("testCipher1.txt", std::ios::binary);
//    //std::ifstream inFile("testCipher2.txt", std::ios::binary);
//    //c.load(context, inFile);
//    //seal::SecretKey secret_key;
//    //secret_key.load(context, inFile2);
//    //inFile.close();
//    //inFile2.close();
//    //seal::Decryptor decryptor(context, secret_key);
//    //decryptor.decrypt(c, p);
//    //std::vector<double> ans;
//    //encoder.decode(p, ans);
//    //std::cout << std::fixed << std::setprecision(2) << ans[0] << std::endl;
//    //c.load(context, inFile3);
//    //inFile3.close();
//    //decryptor.decrypt(c, p);
//    //ans.clear();
//    //encoder.decode(p, ans);
//    //std::cout << std::fixed << std::setprecision(2) << ans[0] << std::endl;
//    //TCPHandler handler;
//    //SOCKET ClientSocket = INVALID_SOCKET;
//    //SOCKET ListenSocket = INVALID_SOCKET;
//    //SOCKET ConnectSocket = INVALID_SOCKET;
//    //handler.initiateListenConnection(DEFAULT_RECEIVE_PORT, ClientSocket, ListenSocket);
//    //handler.initiateSendConnection(DEFAULT_SEND_PORT, ConnectSocket);
//    //handler.transmitFile(ConnectSocket, "testCipher1.txt");
//}

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
#pragma comment(lib, "cpprest_2_10")

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;

using namespace std;


static TransactionList* transactions = new TransactionList();
static DebitList* debits = new DebitList();
static LoginHandler* loginHandler = new LoginHandler();
static TransactionHandler* tran = new TransactionHandler(transactions, debits);
static DBHandler* dat = new DBHandler(loginHandler, tran);
static seal::SecretKey* secret_key = new seal::SecretKey;
static seal::PublicKey* public_key = new seal::PublicKey;
static seal::EncryptionParameters* params = new seal::EncryptionParameters(seal::scheme_type::ckks);
static seal::SEALContext* context = new seal::SEALContext(NULL);
static map<int, wstring> loggedIn;

/* A 256 bit key */
static unsigned char* key = (unsigned char*)"01234567890123456789012345678901";

/* A 128 bit IV */
static unsigned char* iv = (unsigned char*)"0123456789012345";


void loadCKKSParams(seal::EncryptionParameters& params, seal::PublicKey& public_key) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
    seal::SEALContext context(params);
    std::ifstream pubFileIn("publicKeyCKKS.pem", std::ios::binary);
    public_key.load(context, pubFileIn);
    pubFileIn.close();
}


void handle_get(http_request request)
{
    wcout << "Handle GET" << endl;
    wstring h = request.relative_uri().to_string();
    auto index = h.find_first_not_of('/');
    std::wstring fileName;
    fileName = fileName.substr(index, fileName.length());
    wcout << fileName << endl;
    if (!filesystem::exists(fileName)) {
        request.reply(status_codes::BadRequest);
    }
    else {
        auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
        request.reply(status_codes::OK, f.streambuf()).get();
    }
}

void handle_post(http_request request)
{
    wcout << "Handle POST" << endl;
    auto req = request.body();
    auto buf = req.streambuf();
    string result;
    wstring h = request.relative_uri().to_string();
    while (!buf.is_eof()) {
        result += buf.sbumpc();
    }
    auto index = h.find_first_not_of('/');
    std::wstring fileName;
    fileName = fileName.substr(index, fileName.length());
    wcout << fileName << endl;
    std::ofstream outFile(fileName, std::ios::binary);
    outFile << result;
    outFile.close();
    request.reply(status_codes::OK);
}

void handle_put(http_request request)
{
    wcout << "Handle PUT" << endl;
    auto req = request.body();
    auto buf = req.streambuf();
    string result;
    wstring h = request.relative_uri().to_string();
    auto index = h.find_first_not_of('/');
    std::wstring fileName;
    fileName = fileName.substr(index, fileName.length());
    wcout << fileName << endl;
    if (!filesystem::exists(fileName)) {
        request.reply(status_codes::BadRequest);
    }
    else {
        while (!buf.is_eof()) {
            result += buf.sbumpc();
        }
        std::ofstream outFile(fileName, std::ios::binary);
        outFile << result;
        outFile.close();
        request.reply(status_codes::OK);
    }
}

void handle_del(http_request request)
{
    wcout << "Handle DELETE" << endl;
    auto req = request.body();
    wstring h = request.relative_uri().to_string();
    auto index = h.find_first_not_of('/');
    std::wstring fileName;
    fileName = fileName.substr(index, fileName.length());
    wcout << fileName << endl;
    if (!filesystem::exists(fileName)) {
        request.reply(status_codes::BadRequest);
    }
    else {
        if (filesystem::remove(fileName)) {
            request.reply(status_codes::OK);
        }
        else {
            request.reply(status_codes::InternalError);
        }
    }

}

void serverLogin(http_request request) {
    secret_key->load(*context, *new ifstream("privateKeyCKKS.pem", std::ios::binary));
    loadCKKSParams(*params, *public_key);
    wstring id = request.relative_uri().to_string();
    id = id.substr(1, id.length());
    wcout << id << endl;
    wcout << request.get_remote_address() << endl;
    if (loggedIn.contains(stoi(id))) {
        request.reply(status_codes::Conflict);
    }
    Account* acc = dat->getAccount(stoi(id), *context);
    if (acc == nullptr || stoi(id) == 1) { // Checks to see if the account is null or the admin account.
        request.reply(status_codes::BadRequest);
    }
    else {
        wstring pin = L"";
        auto buf = request.body().streambuf();
        while (!buf.is_eof()) {
            pin += buf.sbumpc();
        }
        pin = pin.substr(0, pin.length() - 1);
        wstring actualPin = to_wstring(acc->getHashedPin());
        wcout << pin << endl;
        wcout << actualPin << endl;
        if (pin.compare(actualPin) == 0) {
            loggedIn.insert(pair<int, wstring>(acc->getId(), request.get_remote_address()));
            request.reply(status_codes::OK);
        }
        else {
            request.reply(status_codes::NotAcceptable);
        }
    }
}

void serverLogout(http_request request) {
    wstring id = request.relative_uri().to_string();
    id = id.substr(1, id.length());
    wcout << request.get_remote_address() << endl;
    if (loggedIn.contains(stoi(id))) {
        if (loggedIn.at(stoi(id)).compare(request.get_remote_address()) == 0) {
            loggedIn.erase(stoi(id));
            request.reply(status_codes::OK);
        }
        else {
            request.reply(status_codes::Forbidden);
        }
    }
    else {
        request.reply(status_codes::Forbidden);
    }
}

void serverTransfer(http_request request) {
    wstring uri = request.relative_uri().to_string();
    wcout << uri << endl;
    uri = uri.substr(1, uri.length());
    int idFrom = stoi(uri);
    cout << "ID from: " << idFrom << endl;
    int index = uri.find_first_of(',');
    uri = uri.substr(index+1, uri.length());
    int idTo = stoi(uri);
    cout << "ID to: " << idTo << endl;
    Account* accFrom = dat->getAccount(idFrom, *context);
    Account* accTo = dat->getAccount(idTo, *context);
    if (accTo == nullptr) {
        request.reply(status_codes::BadRequest);
    }
    auto buf = request.body().streambuf();
    wstring amount;
    while (!buf.is_eof()) {
        amount += buf.sbumpc();
    }
    double am = stod(amount);
    cout << "Amount to transfer: " << am << endl;
    if (loggedIn.contains(idFrom)) {
        cout << "idFrom is logged in" << endl;
        if (loggedIn.at(idFrom).compare(request.get_remote_address()) == 0) {
            cout << "request comes from the same IP" << endl;
            seal::CKKSEncoder encoder(*context);
            seal::Encryptor encryptor(*context, *public_key);
            seal::Decryptor decryptor(*context, *secret_key);
            seal::Plaintext plaintext;
            seal::Ciphertext ciphertext;
            cout << "encryption stuff set up" << endl;
            double scale = pow(2, 20);
            encoder.encode(am, scale, plaintext);
            cout << "Amount encoded" << endl;
            encryptor.encrypt(plaintext, ciphertext);
            cout << "Amount encrypted" << endl;
            cout << "We encrypt the amount to send" << endl;
            wstring fileName = to_wstring(idFrom) + L"'" + to_wstring(idTo) + L"'" + to_wstring(time(nullptr));
            ofstream outFile(fileName, std::ios::binary);
            ciphertext.save(outFile);
            outFile.close();
            cout << "We save the amount into a temp file" << endl;
            http_client client(L"http://localhost:8081/balance");
            wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress());
            auto response = client.request(methods::GET, balAddress).get();
            cout << "We request the balance for the sending account" << endl;
            std::ofstream outFile2(balAddress, std::ios::binary);
            auto fileContent = response.body().streambuf();
            string content = "";
            while (!fileContent.is_eof()) {
                content += fileContent.sbumpc();
            }
            outFile2 << content;
            outFile2.close();
            cout << "We write this into its file" << endl;
            vector<double> res;
            ifstream inFile2(accFrom->getBalanceAddress(), std::ios::binary);
            ciphertext.load(*context, inFile2);
            decryptor.decrypt(ciphertext, plaintext);
            encoder.decode(plaintext, res);
            cout << res[0] << endl;
            if (am <= res[0] + accFrom->getOverdraft()) {
                cout << "Can verify that the amount is ok" << endl;
                
                http_client client2(L"http://localhost:8081/transfer");
                auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
                auto response = client2.request(methods::PUT, std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress()) + L"," + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accTo->getBalanceAddress()) + L"," + fileName + L".txt", f.streambuf());
                wcout << response.get().status_code();
                request.reply(status_codes::OK);
            }
            else {
                request.reply(status_codes::BadRequest);
            }
        }
        else {
            request.reply(status_codes::Forbidden);
        }
    }
    else {
        request.reply(status_codes::Forbidden);
    }
}

void serverBalance(http_request request) {
    try {
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        wcout << idTo << endl;
        int id = stoi(idTo);
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                Account* account = dat->getAccount(id, *context);
                cout << account->getBalanceAddress() << endl;
                http_client client(L"http://localhost:8081/balance");
                wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(account->getBalanceAddress());
                auto response = client.request(methods::GET, balAddress).get();
                std::ofstream outFile(balAddress, std::ios::binary);
                auto fileContent = response.body().streambuf();
                string content = "";
                while (!fileContent.is_eof()) {
                    content += fileContent.sbumpc();
                }
                outFile << content;
                outFile.close();
                seal::Decryptor decryptor(*context, *secret_key);
                seal::CKKSEncoder encoder(*context);
                seal::Ciphertext ciphertext;
                seal::Plaintext plaintext;
                ifstream inFile(balAddress, std::ios::binary);
                ciphertext.load(*context, inFile);
                inFile.close();
                vector<double> result;
                decryptor.decrypt(ciphertext, plaintext);
                encoder.decode(plaintext, result);
                request.reply(status_codes::OK, result[0]);
            }
            else {
                request.reply(status_codes::Forbidden);
            }
        }
        else {
            request.reply(status_codes::Forbidden);
        }
    }
    catch (exception& e) {
        cout << e.what();
        request.reply(status_codes::InternalError);
    }
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void test(http_request request) {

    wstring s1 = request.extract_utf16string().get();
    wstring uri = request.relative_uri().to_string();
    uri = uri.substr(1, uri.length());
    int index = uri.find_first_of(',');
    int plaintext_len = stoi(uri.substr(0, index));
    wcout << plaintext_len << endl;
    int ciphertext_len = stoi(uri.substr(index + 1, uri.length()));
    wcout << ciphertext_len << endl;
    char* intermediary = new char[ciphertext_len];
    unsigned char* converted = new unsigned char[ciphertext_len];
    wcstombs(intermediary, s1.c_str(), ciphertext_len);
    converted = reinterpret_cast<unsigned char*>(intermediary);
    unsigned char* final = new unsigned char[ciphertext_len];
    int decrypted_len = decrypt(converted, ciphertext_len, key, iv, final);
    int diff = (ciphertext_len - plaintext_len);
    cout << diff << endl;
    unsigned char pad = (unsigned char)diff;
    cout << pad << endl;
    unsigned char* fin = new unsigned char[decrypted_len];
    for (int i = 0; i < strlen((char*)final); ++i) {
        if (final[i] != pad) {
            fin[i] = final[i];
        }
        else {
            fin[i] = '\0';
            break;
        }
    }
    wcout << L"Ciphertext received: " << s1 << endl;
    cout << "Decrypted message: " << final << endl;
    cout << "Removed padding: " << fin << endl;
    request.reply(status_codes::OK);
}



int main()
{
    //seal::PublicKey public_key;
    //seal::EncryptionParameters params;
    //loadCKKSParams(params, public_key);
    //seal::SEALContext context(params);
    //seal::Plaintext p;
    //seal::CKKSEncoder encoder(context);
    //seal::Encryptor encryptor(context, public_key);
    //seal::Ciphertext c;

    //double scale = pow(2, 20);
    //encoder.encode(1000.00, scale, p);
    //encryptor.encrypt(p, c);
    //std::ofstream out1("testCipher1.txt", std::ios::binary);
    //std::ofstream out2("testCipher2.txt", std::ios::binary);
    //c.save(out1);
    //c.save(out2);
    //out1.close();
    //out2.close();
    //std::cout << "Done!" << std::endl;

    try
    {
        loadCKKSParams(*params, *public_key);
        do {
            seal::SEALContext con(*params);
            context = new seal::SEALContext(con);
        } while (false);
        dat->connectToDB();
        //http_listener listener(L"http://localhost:8080/restdemo");

        //listener.support(methods::GET, handle_get);
        //listener.support(methods::POST, handle_post);
        //listener.support(methods::PUT, handle_put);
        //listener.support(methods::DEL, handle_del);

        http_listener loginListener(L"http://localhost:8080/login");
        loginListener.support(methods::PUT, serverLogin);
        loginListener.support(methods::DEL, serverLogout);

        http_listener transactionListener(L"http://localhost:8080/transfer");
        transactionListener.support(methods::POST, serverTransfer);

        http_listener balanceListener(L"http://localhost:8080/balance");
        transactionListener.support(methods::GET, serverBalance);


        //http_listener lis(L"http://localhost:8080/test");

        //lis.support(methods::PUT, test);

//       listener
//           .open()
//            .then([&listener]() {wcout << (L"Starting to listen") << endl; })
//            .wait();

        loginListener
            .open()
            .then([&loginListener]() { wcout << (L"Starting to listen for logins") << endl; })
            .wait();

        transactionListener
            .open()
            .then([&transactionListener]() {wcout << (L"Starting to listen for transactions") << endl; })
            .wait();

        balanceListener
            .open()
            .then([&balanceListener]() {wcout << (L"Starting to listen for balance requests") << endl; })
            .wait();

        //lis
        //    .open()
        //    .then([&lis]() {wcout << (L"Starting to listen for aes test") << endl; })
        //    .wait();

        while (true);
    }
    catch (exception const& e)
    {
        wcout << e.what() << endl;
    }
    return 0;
}