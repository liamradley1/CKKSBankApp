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

static seal::EncryptionParameters* params = new seal::EncryptionParameters();
static seal::SEALContext* context = new seal::SEALContext(NULL);

void loadCKKSParams(seal::EncryptionParameters& params) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
    seal::SEALContext context2(params);
    context = new seal::SEALContext(context2);
}


void sendBalance(http_request request) {
    wstring fileName = request.relative_uri().to_string();
    fileName = fileName.substr(1, fileName.length());
    wcout << fileName << endl;
    auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
    request.reply(status_codes::OK, f.streambuf());
}

void transaction(http_request request) {
    try {
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
        wcout << "Amount file: " << amountFile << endl;

        // Extract the amount file from the request and create a file for storage
        auto buf = request.body().streambuf();
        string contents = "";
        while (!buf.is_eof()) {
            contents += buf.sbumpc();
        }
        ofstream balOut(amountFile, std::ios::binary);
        balOut << contents;
        balOut.close();

        // Extract the ciphertexts from balance and amount files
        seal::Ciphertext fromBal, toBal, amount;
        ifstream fromIn(fileFrom, std::ios::binary);
        fromBal.load(*context, fromIn);
        fromIn.close();
        cout << "fromBal read in" << endl;
        ifstream toIn(fileTo, std::ios::binary);
        toBal.load(*context, toIn);
        toIn.close();
        cout << "toBal read in" << endl;
        ifstream balIn(amountFile, std::ios::binary);
        amount.load(*context, balIn);
        balIn.close();
        cout << "balIn read in" << endl;

        // Perform encrypted arithmetic on ciphertexts to update balances
        seal::Evaluator evaluator(*context);
        evaluator.sub_inplace(fromBal, amount);
        cout << "Amount deducted" << endl;
        evaluator.add_inplace(toBal, amount);
        cout << "Amount added" << endl;
        evaluator.negate_inplace(amount);
        wcout << "File name: " << amountFile << endl;
        index = amountFile.find_first_of((char)39);
        wstring from = amountFile.substr(0, index);
        wcout << L"From: " << from << endl;
        wcout << L"Remaining file name: " << amountFile << endl;
        amountFile = amountFile.substr(index + 1, amountFile.length());
        index = amountFile.find_first_of((char)39);
        wstring to = amountFile.substr(0, index);
        wcout << L"To: " << to << endl;
        amountFile = amountFile.substr(index + 1, amountFile.length());
        wstring time = amountFile;
        wcout << L"Time: " << time << endl;
        // Write new balances into balance files
        ofstream fromOut(fileFrom, std::ios::binary);
        fromBal.save(fromOut);
        fromOut.close();
        ofstream toOut(fileTo, std::ios::binary);
        toBal.save(toOut);
        toOut.close();
        
        // Reply with the OK message if all goes to plan
        request.reply(status_codes::OK);
    } 
    catch (exception& e) {
        cout << e.what() << endl;
    }
}

void additionalFile(http_request request) { // Provided the .txt file isn't a malicious payload (which is unlikely) we're good. Otherwise this isn't great
                                            // Also it's not ideal how someone can just DOS the cloud server by spamming this link after spoofing the main server's IP and loading up the instance with massive .txt files
    wcout << "Additional file sent" << endl;
    wstring uri = request.relative_uri().to_string();
    wcout << uri << endl;
    uri = uri.substr(1, uri.length());
    wstring type = uri.substr(uri.length() - 4, uri.length());
    wcout << type << endl;
    if(type.compare(L".txt") != 0) {
        request.reply(status_codes::Forbidden);
    }
    else {
        string contents = "";
        auto buf = request.body().streambuf();
        while (!buf.is_eof()) {
            if (buf.getc().get() != -2) {
                contents += buf.sbumpc();
            }
        }
        if (!filesystem::exists(uri)) {
            std::ofstream outFile(uri, std::ios::binary);
                outFile << contents;
                outFile.close();
                request.reply(status_codes::OK);
        }
        else {
            request.reply(status_codes::Forbidden);
        }
    }
}

void directDebit(http_request request) {
    wstring fileName = request.relative_uri().to_string();
    fileName = fileName.substr(1, fileName.length());
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
    request.reply(status_codes::OK);
}

void deleteDebit(http_request request) {
    wstring fileName = request.relative_uri().to_string();
    wcout << fileName << endl;
    fileName = fileName.substr(1, fileName.length());
    string address = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(fileName);
    cout << address << endl;
    remove(address.c_str());
}

int main()
{
    loadCKKSParams(*params);
    http_listener balanceListener(L"http://127.0.0.1:8081/balance");
    balanceListener.support(methods::GET, sendBalance);
    balanceListener
        .open()
        .then([&balanceListener]() {wcout << (L"Starting to listen for balance requests") << endl; })
        .wait();

    http_listener transferListener(L"http://127.0.0.1:8081/transfer");
    transferListener.support(methods::POST, additionalFile);
    transferListener.support(methods::PUT, transaction);
    transferListener
        .open()
        .then([&transferListener]() {wcout << (L"Starting to listen for transaction requests") << endl; })
        .wait();

    http_listener debitListener(L"http://127.0.0.1:8081/debits");
    debitListener.support(methods::POST, directDebit);
    debitListener.support(methods::DEL, deleteDebit);
    debitListener
        .open()
        .then([&debitListener]() {wcout << (L"Starting to listen for direct debit requests") << endl; })
        .wait();

    while (true);
}