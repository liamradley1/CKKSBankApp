// CloudServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <filesystem>
#include <locale>
#include <seal/seal.h>
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

seal::EncryptionParameters* params = new seal::EncryptionParameters();
seal::SEALContext* context = new seal::SEALContext(NULL);
wstring serverIP;


wstring readCloudDNS() {
    try {
        ifstream inFile("cloudDNS.txt");
        string location;
        inFile >> location;
        cout << location << endl;
        return wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(location);
    }
    catch (exception& e) {
        cout << e.what() << endl;
        return NULL;
    }
}

wstring readServerIP() {
    try {
        ifstream inFile("serverIP.txt");
        string location;
        inFile >> location;
        cout << location << endl;
        return wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(location);
    } 
    catch (exception& e) {
        cout << e.what() << endl;
        return NULL;
    }
}

void loadCKKSParams(seal::EncryptionParameters& params) {
    try {
        std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
        params.load(paramsFileIn);
        paramsFileIn.close();
        seal::SEALContext context2(params);
        context = new seal::SEALContext(context2);
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
}


bool sendBalance(http_request request) {
    try {
        wcout << serverIP << endl;
        wcout << request.get_remote_address() << endl;
        if (request.get_remote_address().compare(serverIP) == 0) {
            wstring fileName = request.relative_uri().to_string();
            fileName = fileName.substr(1, fileName.length());
            if (filesystem::exists(fileName)) {
                wcout << fileName << endl;
                auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
                request.reply(status_codes::OK, f.streambuf());
                return true;
            }
            else {
                request.reply(status_codes::NotFound, L"File not found");
                return false;
            }
        }
        else {
            request.reply(status_codes::Forbidden, L"Not authorised to request");
            return false;
        }
    }
    catch (exception& e) {
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

bool transaction(http_request request) {
    try {
        if (request.get_remote_address().compare(serverIP) == 0) {
            // Partition URI into relevant segments
            wstring uri = request.relative_uri().to_string();
            wcout << uri << endl;
            int index = uri.find_first_of(',');
            wstring fileFrom = uri.substr(1, index - 1);
            wcout << "File from: " << fileFrom << endl;
            uri = uri.substr(index + 1, uri.length());
            wcout << "Updated URI: " << uri << endl;
            index = uri.find_first_of(',');
            wstring fileTo = uri.substr(0, index);
            wcout << "File to: " << fileTo << endl;
            uri = uri.substr(index + 1, uri.length());
            wcout << "Updated URI: " << uri << endl;
            wstring amountFile = uri;
            if (amountFile.substr(amountFile.length() - 3, amountFile.length()).compare(L".txt") != 0) {
                cout << "Invalid file type." << endl;
                request.reply(status_codes::BadRequest, L"Invalid file sent");
                return false;
            }
            else if (filesystem::exists(amountFile)) {
                cout << "Attempt to overwrite pre-existing amount file" << endl;
                request.reply(status_codes::BadGateway, L"Invalid file sent");
                return false;
            }
            wcout << "Amount file: " << amountFile << endl;
            if (filesystem::exists(fileFrom)) {
                // Extract the amount file from the request and create a file for storage
                auto buf = request.body().streambuf();
                string contents = "";
                while (!buf.is_eof() && buf.getc().get() != -2) {
                    contents += buf.sbumpc();
                }
                cout << "Writing balance to file" << endl;
                ofstream balOut(amountFile, std::ios::binary);
                balOut << contents;
                balOut.close();
                cout << "Balance written in" << endl;

                // Extract the ciphertexts from balance and amount files
                seal::Ciphertext fromBal, toBal, amount;
                cout << "Getting the balances" << endl;
                ifstream fromIn(fileFrom, std::ios::binary);
                fromBal.load(*context, fromIn);
                fromIn.close();
                cout << "fromBal read in" << endl;
                ifstream balIn(amountFile, std::ios::binary);
                amount.load(*context, balIn);
                balIn.close();
                cout << "balIn read in" << endl;

                // Perform encrypted arithmetic on ciphertexts to update balances
                seal::Evaluator evaluator(*context);
                evaluator.sub_inplace(fromBal, amount);
                cout << "Amount processed" << endl;
                // Write new balances into balance files
                ofstream fromOut(fileFrom, std::ios::binary);
                fromBal.save(fromOut);
                fromOut.close();
                // Reply with the OK message if all goes to plan
                request.reply(status_codes::OK);
                return true;
            }
            else {
                request.reply(status_codes::NotFound, L"File not found.");
                return false;
            }
        }
        else {
            request.reply(status_codes::Forbidden, L"Not authorised to make request");
            return false;
        }
    }
    catch (exception& e) {
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

bool directDebit(http_request request) {
    try {
        if (request.get_remote_address().compare(serverIP) == 0) {
            wstring fileName = request.relative_uri().to_string();
            wcout << fileName << endl;
            fileName = fileName.substr(1, fileName.length());
            if (fileName.length() <= 4) {
                request.reply(status_codes::BadRequest, L"Not a valid file");
                return false;
            }
            wstring type = fileName.substr(fileName.length() - 4, fileName.length());
            if (filesystem::exists(fileName)) {
                request.reply(status_codes::Forbidden, L"File already exists on server");
                return false;
            }
            else if(type.compare(L".txt") != 0) {
                request.reply(status_codes::Forbidden, L"Not a valid file");
                return false;
            }
            else {
                auto buf = request.body().streambuf();
                string contents = "";
                while (!buf.is_eof()) {
                    if (buf.getc().get() != -2) {
                        contents += buf.sbumpc();
                    }
                }
                ofstream outFile(fileName, std::ios::binary);
                outFile << contents;
                outFile.close();
                wcout << fileName << " created." << endl;
                request.reply(status_codes::OK);
                return true;
            }
        }
        request.reply(status_codes::Forbidden, L"Cannot authenticate as the main server");
        return false;
    }
    catch (exception& e) {
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

int main()
{
    try {
        wstring cloudDNS = readCloudDNS();
        serverIP = readServerIP();
        loadCKKSParams(*params);
        http_listener balanceListener(cloudDNS + L":8081/balance");
        balanceListener.support(methods::GET, sendBalance);
        balanceListener
            .open()
            .then([&balanceListener]() {wcout << (L"Starting to listen for balance requests") << endl; })
            .wait();

        http_listener transferListener(cloudDNS + L":8081/transfer");
        transferListener.support(methods::PUT, transaction);
        transferListener
            .open()
            .then([&transferListener]() {wcout << (L"Starting to listen for transaction requests") << endl; })
            .wait();

        http_listener debitListener(cloudDNS + L":8081/debits");
        debitListener.support(methods::POST, directDebit);
        debitListener
            .open()
            .then([&debitListener]() {wcout << (L"Starting to listen for direct debit requests") << endl; })
            .wait();

        while (true);
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
    delete params;
    delete context;
}