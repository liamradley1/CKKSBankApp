// CloudServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
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

void sendBalance(http_request request) {
    wstring fileName = request.relative_uri().to_string();
    fileName = fileName.substr(1, fileName.length());
    wcout << fileName << endl;
    auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
    request.reply(status_codes::OK, f.streambuf()).get();
}

void transaction(http_request request) {
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
    wcout << "Amount file: " <<  amountFile << endl;
    seal::Ciphertext fromBal, toBal, amount;
    request.reply(status_codes::OK);
}

int main()
{
    http_listener balanceListener(L"http://localhost:8081/balance");
    balanceListener.support(methods::GET, sendBalance);
    balanceListener
        .open()
        .then([&balanceListener]() {wcout << (L"Starting to listen for balance requests") << endl; })
        .wait();

    http_listener transferListener(L"http://localhost:8081/transfer");
    transferListener.support(methods::PUT, transaction);
    transferListener
        .open()
        .then([&transferListener]() {wcout << (L"Starting to listen for transaction requests") << endl; })
        .wait();
    while (true);
}