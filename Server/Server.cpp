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
#include <string>
#include <locale>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#include <codecvt>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rsaerr.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sstream>
#include <utility>
#pragma comment(lib, "cpprest_2_10")
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;
using namespace std;


TransactionList* transactions = new TransactionList();
DebitList* debits = new DebitList();
TransactionHandler* tran = new TransactionHandler(transactions, debits);
DBHandler* dat = new DBHandler(tran);
seal::EncryptionParameters* params = new seal::EncryptionParameters(seal::scheme_type::ckks);
seal::SEALContext* context = new seal::SEALContext(NULL);
map<int, wstring> loggedIn;
map<wstring, unsigned char*> ipsAndKeys;
map<wstring, unsigned char*> ipsAndIvs;
map <wstring, int> heartbeats;
int transactionID;
string pubKey;
string priKey;


#define KEY_LENGTH 2048 // Key length
#define AES_BITS 256 // AES Key length
#define PUB_KEY_FILE "serverRSApub.pem" // RSA public key path
#define PRI_KEY_FILE "serverRSApri.pem" // RSA private key path

// Get server DNS from file
wstring readServerDNS() {
    ifstream inFile("serverDNS.txt");
    string location;
    inFile >> location;
    return wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(location);
}

// Get cloud DNS from file
wstring readCloudDNS() {
    ifstream inFile("cloudDNS.txt");
    string location;
    inFile >> location;
    return wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(location);
}

wstring serverDNS = readServerDNS();
wstring cloudDNS = readCloudDNS();

// Generate sessional AES key
void GenerateAESKey(unsigned char* outAESKey, unsigned char* outAESIv) {
    unsigned char* key = new unsigned char[AES_BITS];
    unsigned char* iv = new unsigned char[AES_BITS / 2];
    if (!RAND_bytes(outAESKey, AES_BITS)) {
        cout << "Error creating key." << endl;
    }
    if (!RAND_bytes(outAESIv, AES_BITS / 2)) {
        cout << "Error creating IV." << endl;
    }    
}

// Error handler for AES 
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
}

// Low-level AES encryption function
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Low-level AES decryption function
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// High-level AES encryption function for use with cppRESTSDK
wstring aesEncrypt(string input, unsigned char* key, unsigned char* iv) {
    unsigned char* plaintext = new unsigned char[input.length() * 16];
    unsigned char* ciphertext = new unsigned char[input.length() * 16];
    plaintext = reinterpret_cast<unsigned char*>(const_cast<char*>(input.c_str()));
    int ciphertext_len;
    ciphertext_len = encrypt(plaintext, input.length(), key, iv, ciphertext);
    wstring toSend = L"";
    toSend += to_wstring(ciphertext_len) + L",";
    for (int i = 0; i < ciphertext_len; ++i) {
        toSend += to_wstring((int)ciphertext[i]) + L",";
    }
    return toSend;
}

// High-level AES decryption function for use with cppRESTSDK
string aesDecrypt(wstring input, unsigned char* key, unsigned char* iv) {
    int index = input.find_first_of(L",");
    int ciphertext_len = stoi(input.substr(0, index));
    wstring body = input.substr(index + 1, input.length());
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    unsigned char* plaintext = new unsigned char[ciphertext_len];
    for (int i = 0; i < ciphertext_len; ++i) {
        index = body.find_first_of(L",");
        int toAdd = stoi(body.substr(0, index));
        body = body.substr(index + 1, body.length());
        ciphertext[i] = (unsigned char)toAdd;
    }
    int plaintext_len = decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
    string final = "";
    for (int i = 0; i < plaintext_len; ++i) {
        final += (char)((int)plaintext[i]);
    }
    return final;
}

// Generate RSA keypair
void GenerateRSAKey(std::string& out_pub_key, std::string& out_pri_key)
{
    size_t pri_len = 0; // Private key length
    size_t pub_len = 0; // public key length
    char* pri_key = nullptr; // private key
    char* pub_key = nullptr; // public key

    RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(pub, keypair);
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

    std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
    if (!pub_file.is_open())
    {
        perror("pub key file open fail:");
        return;
    }
    pub_file << pub_key;
    pub_file.close();

    std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
    if (!pri_file.is_open())
    {
        perror("pri key file open fail:");
        return;
    }
    pri_file << pri_key;
    pri_file.close();

    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

// Encrypt data with RSA private key
string RsaPriEncrypt(const std::string& clear_text, std::string& pri_key)
{
    std::string encrypt_text;
    BIO* keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return std::string("");
    }

    int len = RSA_size(rsa);

    char* text = new char[len + 1];
    memset(text, 0, len + 1);

    int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        encrypt_text = std::string(text, ret);
    }

    free(text);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return encrypt_text;
}

// Decrypt data with RSA public key
string RsaPubDecrypt(const std::string& cipher_text, const std::string& pub_key)
{
    std::string decrypt_text;
    BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
    RSA* rsa = RSA_new();

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        unsigned long err = ERR_get_error();
        char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); 
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(keybio);
        return decrypt_text;
    }

    int len = RSA_size(rsa);
    char* text = new char[len + 1];
    memset(text, 0, len + 1);
    int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        decrypt_text.append(std::string(text, ret));
    }

    delete text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}

// Encrypt data with RSA public key
string RsaPubEncrypt(const std::string& clear_text, const std::string& pub_key)
{
    try {
        std::string encrypt_text;
        BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
        RSA* rsa = RSA_new();
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
        if (!rsa) {
            throw new exception("Bad RSA initialisation");
        }
        int key_len = RSA_size(rsa);
        int block_len = key_len - 11; 

        char* sub_text = new char[key_len + 1];
        memset(sub_text, 0, key_len + 1);
        int ret = 0;
        int pos = 0;
        std::string sub_str;
        while (pos < clear_text.length()) {
            sub_str = clear_text.substr(pos, block_len);
            memset(sub_text, 0, key_len + 1);
            ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
            if (ret >= 0) {
                encrypt_text.append(std::string(sub_text, ret));
            }
            pos += block_len;
        }

        BIO_free_all(keybio);
        RSA_free(rsa);
        delete[] sub_text;

        return encrypt_text;
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
}

// Decrypt data with RSA private key
string RsaPriDecrypt(const std::string& cipher_text, const std::string& pri_key)
{
    std::string decrypt_text;
    RSA* rsa = RSA_new();
    BIO* keybio;
    keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa) {
        unsigned long err = ERR_get_error();
        char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg);
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        return std::string();
    }

    int key_len = RSA_size(rsa);
    char* sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    while (pos < cipher_text.length()) {
        sub_str = cipher_text.substr(pos, key_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            decrypt_text.append(std::string(sub_text, ret));
            printf("pos:%d, sub: %s\n", pos, sub_text);
            pos += key_len;
        }
    }
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}

// Upon receiving request from client, authenticate user and retrieve balance from cloud server, then convert from CKKS to AES and send encrypted amount to client
http::status_code getAmount(wstring balAddress, seal::Ciphertext& ciphertext) {
    seal::Ciphertext ciphertext2;
    http_client client(cloudDNS + L":8081/balance");
    wcout << "File requested: " << balAddress << endl;
    auto response = client.request(methods::GET, balAddress);
    auto buf = response.get().body().streambuf();
    if (response.get().status_code() == status_codes::OK) {
        string contents = "";
        while (!buf.is_eof()) {
            if (buf.getc().get() != -2) // Gets rid of weird requiring 'async required' bugs
                contents += buf.sbumpc();
        }
        try {
            ofstream outFile(balAddress, std::ios::binary);
            outFile << contents;
            outFile.close();
            ifstream inFile(balAddress, std::ios::binary | std::ios::beg);
            ciphertext2.load(*context, inFile);
            inFile.close();
            ciphertext = ciphertext2;
            std::remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
            return status_codes::OK;
        }
        catch (exception& e) {
            cout << e.what() << endl;
            return status_codes::NotFound;
        }
    }
    else {
        return status_codes::NotFound;
    }
}

// Function invoked when creating the CKKS params used. Same as what is advised in SEAL documentation
void createAndSaveCKKSParams() {
    seal::EncryptionParameters params(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    seal::SecretKey secret_key;
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    secret_key = keyGen.secret_key();
    std::cout << context.parameter_error_message() << std::endl;
    std::ofstream privFileOut("privateKeyCKKS.pem", std::ios::binary);
    secret_key.save(privFileOut);
    std::cout << "Successfully saved private key." << std::endl;
    privFileOut.close();

    std::ofstream paramsFileOut("paramsCKKS.txt", std::ios::binary);
    params.save(paramsFileOut);
    std::cout << "Successfully saved parameters." << std::endl;
    paramsFileOut.close();
}

// Load CKKS paramaters from file
void loadCKKSParams(seal::EncryptionParameters& params) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
}

// Send RSA-encrypted AES key and IV to requesting client
bool sendKeys(http_request request) {
    try {
        wcout << L"Key request received from IP: " << request.remote_address() << endl;
        wstring uri = request.relative_uri().to_string();
        int length = stoi(uri.substr(1, uri.length()));
        wstring body = request.extract_utf16string().get();
        string rsaKey = "";
        for (int i = 0; i < length; ++i) {
            int index = body.find_first_of(L",");
            int toAdd = stoi(body.substr(0, index));
            rsaKey.push_back(toAdd);
            body = body.substr(index + 1, body.length());
        }
        unsigned char* aesKey = new unsigned char[AES_BITS];
        unsigned char* iv = new unsigned char[AES_BITS / 2];
        string keyToEncrypt = "";
        string ivToEncrypt = "";
        GenerateAESKey(aesKey, iv);
        for (auto const& [key, value] : loggedIn) {
            if (value.compare(request.get_remote_address()) == 0) {
                request.reply(status_codes::Forbidden, L"You are already logged in on this IP.");
                cout << "Attempted key negotiation from the same IP as a logged user." << endl;
                return false;
            }
        }
            ipsAndIvs.erase(request.get_remote_address());
            ipsAndKeys.erase(request.get_remote_address());
            ipsAndIvs.insert(make_pair(request.get_remote_address(), iv));
            ipsAndKeys.insert(make_pair(request.get_remote_address(), aesKey));

            for (int i = 0; i < AES_BITS; ++i) {
                int toAdd = (int)aesKey[i];
                keyToEncrypt += to_string(toAdd) + ",";
            }
            for (int i = 0; i < AES_BITS / 2; ++i) {
                int toAdd = (int)iv[i];
                ivToEncrypt += to_string(toAdd) + ",";
            }
            string toSend = RsaPubEncrypt(keyToEncrypt + "'" + ivToEncrypt, rsaKey);
            request.reply(status_codes::OK, toSend).get();
            wcout << L"Keys negotiated for IP " << request.get_remote_address() << endl;
            return true;
    }
    catch (exception& e) {
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

// Authenticate user and log them in
bool serverLogin(http_request request) {
    try {
        int id = 1;
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring uri = request.relative_uri().to_string();
        uri = uri.substr(1, uri.length());
        wstring body = request.extract_utf16string().get();
        string idToCheck = aesDecrypt(uri, aesKey, iv);
        string pinToCheck = aesDecrypt(body, aesKey, iv);
        int idNum = 0;
        try {
            idNum = stoi(idToCheck);
        }
        catch (exception& e) {
            wcout << "Invalid stoi on user ID: " << idNum << endl << endl;
            request.reply(status_codes::BadRequest, L"Invalid user ID.");
            return false;
        }
        wcout << request.get_remote_address() << endl;
        if (loggedIn.contains(idNum)) {
            wcout << "Duplicate login attempt on account " << idNum << "." << endl << endl;
            request.reply(status_codes::Conflict, L"Unable to log in to this account. Please try again later.");
            return false;
        }
        else {
            Account* acc = dat->getAccount(idNum, *context);
            if (idNum == 1) { // Checks to see if the account is null or the admin account.
                cout << "Attempted login to the admin account." << endl << endl;
                request.reply(status_codes::BadRequest, L"Invalid user ID.");
                delete acc;
                return false;
            }
            else if (acc == nullptr) {
                cout << "Could not find user ID: " << idNum << endl;
                request.reply(status_codes::BadRequest, L"Invalid user ID.");
                delete acc;
                return false;
            }
            else {
                wstring actualPin = to_wstring(acc->getHashedPin());
                wstring pin = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(pinToCheck);
                if (pin.compare(actualPin) == 0) {
                    loggedIn.insert(pair<int, wstring>(acc->getId(), request.get_remote_address()));
                    heartbeats.insert(make_pair(request.get_remote_address(), time(nullptr)));
                    wcout << "Account " << idNum << " logged in." << endl << endl;
                    request.reply(status_codes::OK);
                    delete acc;
                    return true;
                }
                else {
                    wcout << "Unsuccessful login attempt on account" << idNum << endl << endl;
                    request.reply(status_codes::NotAcceptable, L"Some of your login details were wrong. Please try again.");
                    delete acc;
                    return false;
                }
            }
        }
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
    }
}

// Authenticate user and log them out
bool serverLogout(http_request request) {
    try {
        wstring id = request.relative_uri().to_string();
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        id = id.substr(1, id.length());
        int idNum = 0;
        try {
            idNum = stoi(aesDecrypt(id, aesKey, iv));
        }
        catch (exception& e) {
            cout << "Invalid id number in stoi." << endl;
            request.reply(status_codes::BadRequest, L"Your login credentials are incorrect.");
            return false;
        }
        if (loggedIn.contains(idNum)) {
            if (loggedIn.at(idNum).compare(request.get_remote_address()) == 0) {
                loggedIn.erase(idNum);
                wcout << "Account " << idNum << " logged out." << endl << endl;
                delete[] aesKey;
                delete[] iv;
                ipsAndIvs.erase(request.get_remote_address());
                ipsAndKeys.erase(request.get_remote_address());
                heartbeats.erase(request.get_remote_address());
                request.reply(status_codes::OK);
                return true;
            }
            else {
                wcout << "Attempted access to account " << idNum << " from a different IP." << endl << endl;
                request.reply(status_codes::Forbidden, L"Something has gone wrong with your login. Please log in again to continue.");
                return false;
            }
        }
        else {
            wcout << "Attempted access to invalid account ID " << idNum << "." << endl << endl;
            request.reply(status_codes::Forbidden, L"Your login credentials are incorrect.");
            return false;
        }
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

// Receive transaction request. Authenticate user and validity of transaction then execute the transaction
bool serverTransfer(http_request request) {
    try {
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring uri = request.relative_uri().to_string();
        uri = uri.substr(1, uri.length());
        string decrypted = aesDecrypt(uri, aesKey, iv);
        int index = decrypted.find_first_of(",");
        int idTo = 1;
        int idFrom = 1;
        try {
            idFrom = stoi(decrypted.substr(0, index));
            idTo = stoi(decrypted.substr(index + 1, decrypted.length()));
        }
        catch (exception& e) {
            cout << "Invalid account IDs" << endl;
            request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
            return false;
        }
        if (idTo == 1) {
            cout << "Attempted sending of money from account " << idFrom << "to the admin account." << endl << endl;
            request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
            return false;
        }
        else if (idTo == idFrom) {
            cout << "Attempted sending of money from account " << idFrom << " to itself." << endl << endl;
            request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
            return false;
        }
        else {
            Account* accFrom = dat->getAccount(idFrom, *context);
            Account* accTo = dat->getAccount(idTo, *context);
            if (accTo == nullptr) {
                wcout << "Attempt to send money to invalid account with ID " << idTo << "." << endl << endl;
                request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
                delete accFrom;
                delete accTo;
                return false;
            }
            else {
                wstring amount = request.extract_utf16string().get();
                double am = 0.0;
                try {
                    am = stod(aesDecrypt(amount, aesKey, iv));
                }
                catch (exception& e) {
                    cout << "Unable to read the amount desired to be sent." << endl;
                    request.reply(status_codes::BadRequest, L"Invalid amount to be sent.");
                    delete accFrom;
                    delete accTo;
                    return false;
                }
                cout << "Amount to transfer: " << am << endl;
                if (loggedIn.contains(idFrom)) {
                    if (loggedIn.at(idFrom).compare(request.get_remote_address()) == 0) {
                        seal::CKKSEncoder encoder(*context);
                        seal::SecretKey secret_keyFrom;
                        seal::SecretKey secret_keyTo;
                        string keyAddressFrom = accFrom->getKeyAddress();
                        string keyAddressTo = accTo->getKeyAddress();
                        ifstream keyIn(keyAddressFrom, std::ios::binary);
                        secret_keyFrom.load(*context, keyIn);
                        keyIn.close();
                        ifstream keyIn2(keyAddressTo, std::ios::binary);
                        secret_keyTo.load(*context, keyIn2);
                        keyIn2.close();
                        seal::Encryptor encryptorFrom(*context, secret_keyFrom);
                        seal::Encryptor encryptorTo(*context, secret_keyTo);
                        seal::Decryptor decryptor(*context, secret_keyFrom);
                        seal::Plaintext plaintext;
                        seal::Ciphertext ciphertext;
                        double scale = pow(2, 20);
                        encoder.encode(am, scale, plaintext);
                        encryptorFrom.encrypt_symmetric(plaintext, ciphertext);
                        time_t nowTime = time(nullptr);
                        transactionID = dat->getTransactionID() + 1;
                        wstring fileName = to_wstring(idFrom) + L"'" + to_wstring(idTo) + L"'" + to_wstring(transactionID) + L".txt";
                        std::ofstream outFile(fileName, std::ios::binary);
                        ciphertext.save(outFile);
                        outFile.close();
                        wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress());
                        vector<double> res;
                        status_code code = getAmount(balAddress, ciphertext);
                        if (code != status_codes::OK) {
                            cout << "Could not access balance on cloud server." << endl;
                            delete accFrom;
                            delete accTo;
                            request.reply(status_codes::InternalError);
                        }
                        remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
                        decryptor.decrypt(ciphertext, plaintext);
                        encoder.decode(plaintext, res);
                        if (am <= res[0] + accFrom->getOverdraft() && am > 0.00999) {
                            // Send the first file
                            http_client client2(cloudDNS + L":8081/transfer");
                            auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
                            wstring toSendFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress()) + L"," + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accTo->getBalanceAddress()) + L"," + fileName;
                            auto response = client2.request(methods::PUT, toSendFile, f.streambuf()).get();
                            if (response.status_code() == status_codes::OK) {
                                // Send the second file
                                am = -am;
                                encoder.encode(am, scale, plaintext);
                                encryptorTo.encrypt_symmetric(plaintext, ciphertext);
                                fileName = to_wstring(idTo) + L"'" + to_wstring(idFrom) + L"'" + to_wstring(transactionID) + L".txt";
                                ofstream outFile2(fileName, std::ios::binary);
                                ciphertext.save(outFile2);
                                outFile2.close();
                                toSendFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accTo->getBalanceAddress()) + L"," + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress()) + L"," + fileName;
                                f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
                                response = client2.request(methods::PUT, toSendFile, f.streambuf()).get();
                                if (response.status_code() == status_codes::OK) {
                                    dat->logTransaction(accFrom, accTo, nowTime, transactionID);
                                    cout << "Transferred successful from " << idFrom << " to " << idTo << " for amount " << (char)156 << -am << "." << endl << endl;
                                    request.reply(status_codes::OK);
                                    delete accFrom;
                                    delete accTo;
                                    return true;
                                }
                            }
                            cout << "Error on cloud server." << endl;
                            request.reply(status_codes::InternalError);
                            delete accFrom;
                            delete accTo;
                            return false;
                        }
                        else {
                            cout << "Attempted transaction with invalid amount." << endl << endl;
                            request.reply(status_codes::BadRequest, L"You don't have enough in your account. Please try again.");
                            delete accFrom;
                            delete accTo;
                            return false;
                        }
                    }
                    else {
                        wcout << "Attempted access to account " << idFrom << " from a different IP." << endl << endl;
                        request.reply(status_codes::Conflict);
                        delete accFrom;
                        delete accTo;
                        return false;
                    }
                }
                else {
                    wcout << "Attempted access to logged out account " << idFrom << "." << endl << endl;
                    request.reply(status_codes::Conflict);
                    delete accFrom;
                    delete accTo;
                    return false;
                }
            }
            delete accFrom;
            delete accTo;
        }
    }
    catch (exception& e) {
        string errmsg = e.what();
        if (errmsg.compare("invalid stoi argument") == 0 || errmsg.compare("invalid stod argument") == 0) {
            request.reply(status_codes::BadRequest);
            wcout << "Invalid input in transaction" << endl << endl;
            return false;
        }
        else {
            cout << "Internal error occurred." << endl;
            cout << e.what() << endl << endl;;
            request.reply(status_codes::InternalError);
            return false;
        }
    }
}

// Authenticate user and get their balance from the server. Then send balance to client
bool serverBalance(http_request request) {
    try {
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] aesKey;
            delete[] iv;
            cout << e.what() << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        string idToCheck = aesDecrypt(idTo, aesKey, iv);
        cout << "Request for balance from: " << idToCheck << endl;
        int id = 0;
        try {
            id = stoi(idToCheck);
        }
        catch (exception& e) {
            cout << "Stoi error on id." << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                Account* account = dat->getAccount(id, *context);
                string keyAddress = account->getKeyAddress();
                wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(account->getBalanceAddress());
                ifstream keyIn(keyAddress, std::ios::binary);
                seal::SecretKey secret_key;
                secret_key.load(*context, keyIn);
                keyIn.close();
                seal::Decryptor decryptor(*context, secret_key);
                seal::CKKSEncoder encoder(*context);
                seal::Ciphertext ciphertext;
                seal::Plaintext plaintext;
                vector<double> result;
                http::status_code code = getAmount(balAddress, ciphertext);
                if (code == status_codes::OK) {
                    decryptor.decrypt(ciphertext, plaintext);
                    encoder.decode(plaintext, result);
                    string toEncrypt = to_string(result[0]);
                    wstring toSend = aesEncrypt(toEncrypt, aesKey, iv);
                    request.reply(status_codes::OK, toSend);
                    std::remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
                    delete account;
                    return true;
                }
                else {
                    cout << "Information for " << id << " not found on cloud server." << endl;
                    request.reply(status_codes::NotFound, "Cannot locate account. Please contact an administrator.");
                    delete account;
                    return false;
                }
            }
            else {
                wcout << "Attempted access to account " << idTo << " from a different IP." << endl << endl;
                request.reply(status_codes::Forbidden, L"Something has gone wrong with your login. Please log in again to continue.");
                return false;
            }
        }
        else {
            wcout << "Attempted access to logged out account " << idTo << "." << endl << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
    }
    catch (exception& e) {
        wcout << "Internal error occurred:" << endl;
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

// Authenticate user and request history from cloud server. Send this to the requesting client
bool serverHistory(http_request request) {
    try {
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        int id = 0;
        try {
            id = stoi(aesDecrypt(idTo, aesKey, iv));
        }
        catch (exception& e) {
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                TransactionList* transactionList = dat->getTransactions(id, *context);
                std::string details = "";
                if (transactionList == nullptr) {
                    details = "No transactions have occurred on this account.";
                    wstring toSend = aesEncrypt(details, aesKey, iv);
                    request.reply(status_codes::OK, toSend);
                    return true;
                }
                else {
                    for (Transaction* transaction : transactionList->getTransactions()) {
                        details += transaction->printTransaction();
                        wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(transaction->getAmount());
                        Account* account = dat->getAccount(id, *context);
                        seal::Ciphertext ciphertext;
                        seal::Plaintext plaintext;
                        vector<double> res;
                        seal::SecretKey secret_key;
                        ifstream keyIn(account->getKeyAddress(), std::ios::binary);
                        secret_key.load(*context, keyIn);
                        keyIn.close();
                        seal::Decryptor decryptor(*context, secret_key);
                        seal::CKKSEncoder encoder(*context);
                        http::status_code code = getAmount(balAddress, ciphertext);
                        if (code != status_codes::OK) {
                            cout << "Could not access file on cloud server." << endl;
                            request.reply(status_codes::InternalError);
                            for (Transaction* t : transactionList->getTransactions()) {
                                transactions->removeTransaction(t);
                            }
                            return false;
                        }
                        decryptor.decrypt(ciphertext, plaintext);
                        encoder.decode(plaintext, res);
                        std::stringstream ss;
                        ss << fixed << setprecision(2) << abs(res[0]);
                        string bal;
                        ss >> bal;
                        details += bal;
                        details += "\n";
                        transactions->removeTransaction(transaction);
                    }
                    cout << "Account " << id << " requested their transactions history." << endl << endl;
                    wstring toSend = aesEncrypt(details, aesKey, iv);
                    request.reply(status_codes::OK, toSend);
                    _CrtDumpMemoryLeaks();
                    return true;
                }
            }
        }
        request.reply(status_codes::Forbidden, L"Invalid login credentials");
        return false;
    }
    catch (exception& e) {
        cout << "Internal error occurred: " << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

// Authenticate user and collect debits on account from the cloud server. Send these to the requesting client
bool serverDebits(http_request request) {
    try {
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        idTo = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(aesDecrypt(idTo, aesKey, iv));
        int id = 0;
        try {
            id = stoi(idTo);
        }
        catch (exception& e) {
            wcout << "Invalid stoi request on id " << idTo << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        string details = "";
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                DebitList* debits = dat->queryDebits(*context);
                if (debits == nullptr) {
                    details = "No debits exist on this account.\n";
                }
                else {
                    int counter = 0;
                    for (DirectDebit* debit : debits->getDebits()) {
                        if (debit->getFrom()->getId() == id) {
                            counter++;
                            details += debit->printDebitInfo();
                            seal::Ciphertext ciphertext;
                            wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(debit->getAmountAddress());
                            getAmount(balAddress, ciphertext);
                            seal::SecretKey secret_key;
                            ifstream keyIn(debit->getFrom()->getKeyAddress(), std::ios::binary);
                            secret_key.load(*context, keyIn);
                            keyIn.close();
                            seal::Plaintext plaintext;
                            seal::CKKSEncoder encoder(*context);
                            seal::Decryptor decryptor(*context, secret_key);
                            vector<double> res;
                            decryptor.decrypt(ciphertext, plaintext);
                            encoder.decode(plaintext, res);
                            std::stringstream ss;
                            ss << fixed << setprecision(2) << abs(res[0]);
                            string result;
                            ss >> result;
                            details += result;
                            details += " \n";
                            remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
                        }
                    }
                }
                if (details.compare("") == 0) {
                    details = "No debits exist on this account.\n";
                }
                wstring toSend = aesEncrypt(details, aesKey, iv);
                request.reply(status_codes::OK, toSend);
                delete debits;
                return true;
            }
        }
        request.reply(status_codes::Forbidden, L"Invalid login credentials");
        return false;
    }
    catch (exception& e) {
        cout << "Internal error occurred: " << endl;
        cout << e.what() << endl;
        if (((string)e.what()).compare("I/O error: input stream ended unexpectedly") == 0) {
            cout << "This is probably due to a necessary file being missing on the cloud server." << endl;
        }
        request._reply_if_not_already(status_codes::InternalError);
        return false;
    }
}

// Add direct debit to account and store details on cloud server
bool serverAddDebits(http_request request) {
    try {
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            cout << "Invalid login credentials on request" << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            cout << "Invalid login credentials on request" << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring idFrom = request.relative_uri().to_string();
        idFrom = idFrom.substr(1, idFrom.length());
        int id;
        try {
            id = stoi(aesDecrypt(idFrom, aesKey, iv));
        }
        catch (exception& e) {
            cout << "Bad account ID conversion" << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                Account* from = dat->getAccount(id, *context);
                wstring details = request.extract_utf16string().get();
                string decrypted = aesDecrypt(details, aesKey, iv);
                details = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(decrypted);
                int index = details.find_first_of(L",");
                wstring idString = details.substr(0, index);
                details = details.substr(index + 1, details.length());
                index = details.find_first_of(L",");
                wstring regularity = details.substr(0, index);
                details = details.substr(index + 1, details.length());
                wstring amountString = details;
                Account* to = nullptr;
                try {
                    to = dat->getAccount(stoi(idString), *context);
                }
                catch (exception& e) {
                    cout << "Bad account ID conversion for send request from account " << id << endl << endl;
                    request.reply(status_codes::BadRequest, L"Invalid recipient account. Please try again.");
                    return false;
                }
                if (stoi(idString) == 1) {
                    cout << "Attempt to send to admin account" << endl;
                    request.reply(status_codes::BadRequest, L"Invalid recipient account. Please try again.");
                    return false;
                }
                DebitList* debitList = dat->queryDebits(*context);
                bool exists = false;
                if (to == nullptr) {
                    cout << "Attempting to send money to an invalid account." << endl;
                    request.reply(status_codes::BadRequest, L"Invalid recipient account. Please try again.");
                    return false;
                }
                else if (from->getId() == to->getId()) {
                    cout << "User number " << id << " attempted to create a direct debit to themselves." << endl << endl;
                    request.reply(status_codes::BadRequest, L"Invalid recipient account. Please try again.");
                    return false;
                }
                else {
                    string regString = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(regularity);
                    cron::cronexpr expression;
                    bool validCron = true;
                    try {
                        expression = cron::make_cron(regString);
                    }
                    catch (exception& e) {
                        cout << "User " << id << " sent a bad cron expression." << endl << endl;
                        request.reply(status_codes::BadRequest, L"Invalid regularity. Please try again.");
                        return false;
                    }
                        seal::SecretKey secret_key;
                        ifstream keyIn(from->getKeyAddress(), std::ios::binary);
                        secret_key.load(*context, keyIn);
                        keyIn.close();
                        seal::Encryptor encryptor(*context, secret_key);
                        seal::CKKSEncoder encoder(*context);
                        double amount = 0.0;
                        try {
                            amount = stod(amountString);
                        }
                        catch (exception& e) {
                            cout << "Bad stod conversion on amount string from user " << id << endl << endl;
                            request.reply(status_codes::BadRequest, L"Invalid amount. Please try again.");
                        }
                        if (amount != 0.0) {
                            double scale = pow(2, 20);
                            seal::Plaintext plaintext;
                            encoder.encode(amount, scale, plaintext);
                            seal::Ciphertext ciphertext;
                            encryptor.encrypt_symmetric(plaintext, ciphertext);
                            time_t nowTime = time(nullptr);
                            string address = to_string(id) + "'" + std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(idString) + "'" + to_string(nowTime) + ".txt";
                            ofstream outFile(address, std::ios::binary);
                            ciphertext.save(outFile);
                            outFile.close();
                            wstring toSend = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(address);
                            http_client client(cloudDNS + L":8081/debits");
                            auto f = file_stream<char>::open_istream(toSend, std::ios::binary).get();
                            auto response = client.request(methods::POST, toSend, f.streambuf());
                            if (response.get().status_code() == status_codes::OK) {
                                DirectDebit* debit = new DirectDebit(0, from, to, address, expression, nowTime);
                                dat->addDebit(debit, regString, *context, *params);
                                cout << "Direct debit created from account " << from->getId() << " to account " << to->getId() << endl;
                                delete debit;
                                request.reply(status_codes::OK, L"Debit created successfully!");
                                delete from;
                                delete to;
                                delete debitList;
                                return true;
                            }
                            request.reply(status_codes::InternalError, L"Internal error when locating your files. Please contact an administrator");
                            return false;
                        }
                    }
            }
        }
        request.reply(status_codes::Forbidden, L"Invalid login credentials");
        return false;
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

// Remove direct debit from account
bool serverRemoveDebit(http_request request) {
    try {
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = new unsigned char[2];
        unsigned char* iv = new unsigned char[2];
        try {
            aesKey = ipsAndKeys.at(ip);
        }
        catch (exception& e) {
            cout << e.what() << endl;
            delete[] aesKey;
            cout << "Invalid credentials presented" << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        try {
            iv = ipsAndIvs.at(ip);
        }
        catch (exception& e) {
            delete[] iv;
            delete[] aesKey;
            cout << e.what() << endl;
            cout << "Invalid credentials presented" << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        wstring idFrom = request.relative_uri().to_string();
        idFrom = idFrom.substr(1, idFrom.length());
        idFrom = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(aesDecrypt(idFrom, aesKey, iv));
        int id = 0;
        try {
            id = stoi(idFrom);
        }
        catch (exception& e) {
            cout << "Invalid stoi from id" << endl;
            request.reply(status_codes::Forbidden, L"Invalid login credentials");
            return false;
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                Account* acc = dat->getAccount(id, *context);
                wstring debitId = request.extract_utf16string().get();
                int deb = 0;
                try {
                    deb = stoi(aesDecrypt(debitId, aesKey, iv));
                }
                catch (exception& e) {
                    cout << "Invalid stoi conversion on direct debit ID" << endl << endl;
                    request.reply(status_codes::BadRequest, L"Invalid debit ID");
                    delete acc;
                    return false;
                }
                DebitList* debits = dat->queryDebits(*context);
                if (debits == nullptr) {
                    delete acc;
                    delete debits;
                    cout << "No debits exist to check" << endl;
                    request.reply(status_codes::NotFound, L"Invalid debit ID");
                    return false;
                }
                else {
                    for (DirectDebit* d : debits->getDebits())
                    {
                        if (d->getId() == deb) {
                            if (d->getFrom()->getId() == id) {
                                dat->removeDebit(d->getId());
                                std::string address = d->getAmountAddress();
                                wstring add = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(address);
                                cout << address << endl;

                                http_client client(cloudDNS + L":8081/debits");
                                debits->removeDebit(d);
                                remove(address.c_str());
                                cout << "Deleted debit with ID" << id << endl;
                                request.reply(status_codes::OK, L"Debit deleted!");
                                delete debits;
                                delete acc;
                                return true;
                            }
                        }
                    }
                    cout << "Debit not found" << endl;
                    request.reply(status_codes::NotFound, L"Invalid debit ID");
                    delete debits;
                    delete acc;
                    return false;
                }
            }
        }
        request.reply(status_codes::Forbidden, L"Invalid login credentials");
        return false;
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
        return false;
    }
}

// Reply to client-sent heartbeat
bool replyToHeartbeat(http_request request) {
    try {
        heartbeats.at(request.get_remote_address()) = time(nullptr);
        request.reply(status_codes::OK);
        return true;
    }
    catch (exception& e) {
        cout << e.what() << endl;
        request.reply(status_codes::BadRequest, L"Invalid heartbeat request");
        return false;
    }
}

// Check that logged in users have sent a heartbeat in the last 15 seconds. If not, forcibly log them out
void checkHeartbeats() {
    while (true) {
        try {
            for (auto const& [ip, lastHeartbeat] : heartbeats) {
                if (lastHeartbeat < time(nullptr) - 15) {
                    ipsAndIvs.erase(ip);
                    ipsAndKeys.erase(ip);
                    cout << "Forcibly logging out unresponsive account." << endl;
                    for (auto const& [id, ip2] : loggedIn) {
                        if (ip2.compare(ip) == 0) {
                            heartbeats.erase(ip);
                            loggedIn.erase(id);
                            ipsAndIvs.erase(ip);
                            ipsAndKeys.erase(ip);
                            cout << "Logged out account " << to_string(id) << endl;
                        }
                    }
                }
            }
            _sleep(14800);
        }
        catch (exception& e) {
            cout << e.what() << endl;
        }
    }
}

int main()
{
    std::thread heartbeatThread(checkHeartbeats);

    try {

        loadCKKSParams(*params);
        do {
            seal::SEALContext con(*params);
            context = new seal::SEALContext(con);
        } while (false);
        dat->connectToDB();
        transactionID = dat->getTransactionID();
        http_listener loginListener(serverDNS + L":8080/login");
        loginListener.support(methods::PUT, serverLogin);
        loginListener.support(methods::DEL, serverLogout);

        http_listener transactionListener(serverDNS + L":8080/transfer");
        transactionListener.support(methods::POST, serverTransfer);

        http_listener balanceListener(serverDNS + L":8080/balance");
        transactionListener.support(methods::GET, serverBalance);

        http_listener historyListener(serverDNS + L":8080/history");
        historyListener.support(methods::GET, serverHistory);

        http_listener debitListener(serverDNS + L":8080/debits");
        debitListener.support(methods::GET, serverDebits);
        debitListener.support(methods::POST, serverAddDebits);
        debitListener.support(methods::DEL, serverRemoveDebit);

        http_listener keyListener(serverDNS + L":8080/requestkey");
        keyListener.support(methods::POST, sendKeys);

        http_listener heartbeatListener(serverDNS + L":8080/heartbeat");
        heartbeatListener.support(methods::GET, replyToHeartbeat);

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

        historyListener
            .open()
            .then([&historyListener]() {wcout << (L"Starting to listen for history requests") << endl; })
            .wait();

        debitListener
            .open()
            .then([&debitListener]() {wcout << (L"Starting to listen for debit requests") << endl; })
            .wait();

        keyListener
            .open()
            .then([&keyListener]() {wcout << ("Starting to listen for key exchanges") << endl; })
            .wait();

        heartbeatListener
            .open()
            .then([&heartbeatListener]() {wcout << ("Starting to listen for client heartbeats") << endl; })
            .wait();
        while (true);
        heartbeatThread.join();
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
    // Delete all pointers
    delete transactions;
    delete debits;
    delete tran;
    delete dat;
    delete params;
    delete context;
    for (auto const& [key, value] : ipsAndIvs) {
        delete[] value;
    }
    for (auto const& [key, value] : ipsAndKeys) {
        delete[] value;
    }
}