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

void GenerateAESKey(unsigned char* outAESKey, unsigned char* outAESIv) {
    unsigned char* key = new unsigned char[AES_BITS];
    unsigned char* iv = new unsigned char[AES_BITS / 2];
    if (!RAND_bytes(outAESKey, AES_BITS)) {
        cout << "Error creating key." << endl;
    }
    if ( !RAND_bytes(outAESIv, AES_BITS / 2)) {
        cout << "Error creating IV." << endl;
    }
    cout << "AES key: " << endl;
    for (int i = 0; i < AES_BITS; ++i) {
        cout << (int)outAESKey[i];
    }cout << endl;
    cout << "IV: " << endl;
    for (int i = 0; i < AES_BITS / 2; ++i) {
        cout << (int)outAESIv[i];
    }cout << endl;
    cout << endl;
}
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
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
    wcout << "Encrypted message sent: " << toSend << endl;
    return toSend;
}
string aesDecrypt(wstring input, unsigned char* key, unsigned char* iv) {
    int index = input.find_first_of(L",");
    int ciphertext_len = stoi(input.substr(0, index));
    cout << "Length: " << ciphertext_len << endl;
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
void GenerateRSAKey(std::string& out_pub_key, std::string& out_pri_key)
{
    size_t pri_len = 0; // Private key length
    size_t pub_len = 0; // public key length
    char* pri_key = nullptr; // private key
    char* pub_key = nullptr; // public key

    // Generate key pair
    RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    // Generate private key
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    // Note------Generate the public key in the first format
//PEM_write_bio_RSAPublicKey(pub, keypair);
     // Note------Generate the public key in the second format (this is used in the code here)
    PEM_write_bio_RSA_PUBKEY(pub, keypair);
    // Get the length  
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // The key pair reads the string  
    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

    // Write the public key to the file
    std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
    if (!pub_file.is_open())
    {
        perror("pub key file open fail:");
        return;
    }
    pub_file << pub_key;
    pub_file.close();

    // write private key to file
    std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
    if (!pri_file.is_open())
    {
        perror("pri key file open fail:");
        return;
    }
    pri_file << pri_key;
    pri_file.close();

    // release memory
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}
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

    // Get the maximum length of data that RSA can process at a time
    int len = RSA_size(rsa);

    // Apply for memory: store encrypted ciphertext data
    char* text = new char[len + 1];
    memset(text, 0, len + 1);

    // Encrypt the data with a private key (the return value is the length of the encrypted data)
    int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        encrypt_text = std::string(text, ret);
    }

    // release memory  
    free(text);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return encrypt_text;
}
string RsaPubDecrypt(const std::string& cipher_text, const std::string& pub_key)
{
    std::string decrypt_text;
    BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
    RSA* rsa = RSA_new();

    // Note--------Use the public key in the first format for decryption
   //rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    // Note--------Use the public key in the second format for decryption (we use this format as an example)
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        unsigned long err = ERR_get_error(); //Get the error number
        char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // Format: error:errId: library: function: reason
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(keybio);
        return decrypt_text;
    }

    int len = RSA_size(rsa);
    char* text = new char[len + 1];
    memset(text, 0, len + 1);
    // Decrypt the ciphertext
    int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        decrypt_text.append(std::string(text, ret));
    }

    // release memory  
    delete text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}
string RsaPubEncrypt(const std::string& clear_text, const std::string& pub_key)
{
    try {
        std::string encrypt_text;
        BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
        RSA* rsa = RSA_new();
        // Note the public key in the first format
       //rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
        // Note the public key in the second format (here we take the second format as an example)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
        if (!rsa) {
            throw new exception("Bad RSA initialisation");
        }
        // Get the maximum length of the data block that RSA can process at a time
        int key_len = RSA_size(rsa);
        int block_len = key_len - 11; // Because the filling method is RSA_PKCS1_PADDING, so you need to subtract 11 from the key_len

        // Apply for memory: store encrypted ciphertext data
        char* sub_text = new char[key_len + 1];
        memset(sub_text, 0, key_len + 1);
        int ret = 0;
        int pos = 0;
        std::string sub_str;
        // Encrypt the data in segments (the return value is the length of the encrypted data)
        while (pos < clear_text.length()) {
            sub_str = clear_text.substr(pos, block_len);
            memset(sub_text, 0, key_len + 1);
            ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
            if (ret >= 0) {
                encrypt_text.append(std::string(sub_text, ret));
            }
            pos += block_len;
        }

        // release memory  
        BIO_free_all(keybio);
        RSA_free(rsa);
        delete[] sub_text;

        return encrypt_text;
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
}
string RsaPriDecrypt(const std::string& cipher_text, const std::string& pri_key)
{
    std::string decrypt_text;
    RSA* rsa = RSA_new();
    BIO* keybio;
    keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa) {
        unsigned long err = ERR_get_error(); //Get the error number
        char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // Format: error:errId: library: function: reason
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        return std::string();
    }

    // Get the maximum length of RSA single processing
    int key_len = RSA_size(rsa);
    char* sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    // Decrypt the ciphertext in segments
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
    // release memory  
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}
void getAmount(wstring balAddress, seal::Ciphertext& ciphertext) {
    seal::Ciphertext ciphertext2;
    http_client client(L"http://ec2-52-90-156-60.compute-1.amazonaws.com:8081/balance");
    auto response = client.request(methods::GET, balAddress);
    auto buf = response.get().body().streambuf();
    cout << response.get().status_code() << endl;
    string contents = "";
    while (!buf.is_eof()) {
        if (buf.getc().get() != -2) // Gets rid of weird requiring 'async required' bugs
            contents += buf.sbumpc();
    }
    cout << "About to write to file" << endl;
    ofstream outFile(balAddress, std::ios::binary);
    cout << contents << endl;
    outFile << contents;
    outFile.close();
    ifstream inFile(balAddress, std::ios::binary | std::ios::beg);
    ciphertext2.load(*context, inFile);
    inFile.close();
    ciphertext = ciphertext2;
    std::remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
}
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
void loadCKKSParams(seal::EncryptionParameters& params) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
}
void sendKeys(http_request request) {
    try {
        wcout << L"Key request received from IP: " << request.remote_address() << endl;
        wstring uri = request.relative_uri().to_string();
        wcout << uri << endl;
        int length = stoi(uri.substr(1, uri.length()));
        cout << "Length: " << length << endl;
        wstring body = request.extract_utf16string().get();
        string rsaKey = "";
        for (int i = 0; i < length; ++i) {
            int index = body.find_first_of(L",");
            int toAdd = stoi(body.substr(0, index));
            rsaKey.push_back(toAdd);
            body = body.substr(index + 1, body.length());
        }
        cout << rsaKey << endl;
        unsigned char* aesKey = new unsigned char[AES_BITS];
        unsigned char* iv = new unsigned char[AES_BITS / 2];
        string keyToEncrypt = "";
        string ivToEncrypt = "";
        GenerateAESKey(aesKey, iv);
        
        unsigned char* keyCopy = new unsigned char[AES_BITS];
        unsigned char* ivCopy = new unsigned char[AES_BITS / 2];

        memcpy(keyCopy, aesKey, AES_BITS);
        memcpy(ivCopy, iv, AES_BITS / 2);
        bool isLoggedIn = false;
        for (auto const& [key, value] : loggedIn) {
            if (value.compare(request.get_remote_address()) == 0) {
                isLoggedIn = true;
                break;
            }
        }
        if(!isLoggedIn) {
            ipsAndIvs.erase(request.get_remote_address());
            ipsAndKeys.erase(request.get_remote_address());
            ipsAndIvs.insert(make_pair(request.get_remote_address(), ivCopy));
            ipsAndKeys.insert(make_pair(request.get_remote_address(), keyCopy));

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
            cout << "Keys negotiated." << endl;
        }
        else {
            request.reply(status_codes::Forbidden, L"You're already logged in on this IP.");
        }
    }
    catch (exception& e) {
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
    }
}

void serverLogin(http_request request) {
    try {
        int id = 1;
        wstring ip = request.get_remote_address();
        unsigned char* aesKey = ipsAndKeys.at(ip);
        unsigned char* iv = ipsAndIvs.at(ip);
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
            request.reply(status_codes::BadRequest);
        }
        wcout << request.get_remote_address() << endl;
        if (loggedIn.contains(idNum)) {
            wcout << "Duplicate login attempt on account " << idNum << "." << endl << endl;
            request._reply_if_not_already(status_codes::Conflict);
        }
        else {
            Account* acc = dat->getAccount(idNum, *context);
            if (acc == nullptr || idNum == 1) { // Checks to see if the account is null or the admin account.
                cout << "Attempted login to the admin account." << endl << endl;
                request._reply_if_not_already(status_codes::BadRequest);
            }
            else {
                wstring actualPin = to_wstring(acc->getHashedPin());
                wstring pin = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(pinToCheck);
                if (pin.compare(actualPin) == 0) {
                    loggedIn.insert(pair<int, wstring>(acc->getId(), request.get_remote_address()));
                    heartbeats.insert(make_pair(request.get_remote_address(), time(nullptr)));
                    wcout << "Account " << idNum << " logged in." << endl << endl;

                    request._reply_if_not_already(status_codes::OK);
                }
                else {
                    wcout << "Unsuccessful login attempt on account" << idNum << endl << endl;
                    request._reply_if_not_already(status_codes::NotAcceptable);
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

void serverLogout(http_request request) {
    try {
        wstring id = request.relative_uri().to_string();
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        id = id.substr(1, id.length());
        int idNum = 0;
        try {
            idNum = stoi(aesDecrypt(id, aesKey, iv));
        }
        catch (exception& e) {
            cout << "Invalid id number in stoi." << endl;
            request.reply(status_codes::BadRequest);
        }
        if (loggedIn.contains(idNum)) {
            if (loggedIn.at(idNum).compare(request.get_remote_address()) == 0) {
                loggedIn.erase(idNum);
                wcout << "Account " << idNum << " logged out." << endl << endl;
                delete[] ipsAndIvs.at(request.get_remote_address());
                delete[] ipsAndKeys.at(request.get_remote_address());
                ipsAndIvs.erase(request.get_remote_address());
                ipsAndKeys.erase(request.get_remote_address());
                request.reply(status_codes::OK);
            }
            else {
                wcout << "Attempted access to account " << idNum << " from a different IP." << endl << endl;
                request.reply(status_codes::Forbidden);
            }
        }
        else {
            wcout << "Attempted access to invalid account ID " << idNum << "." << endl << endl;
            request.reply(status_codes::Forbidden);
        }
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
    }
}

void serverTransfer(http_request request) {
    try {
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        wstring uri = request.relative_uri().to_string();
        uri = uri.substr(1, uri.length());
        string decrypted = aesDecrypt(uri, aesKey, iv);
        cout << decrypted << endl;
        int index = decrypted.find_first_of(",");
        int idTo = 1;
        int idFrom = 1;
        try {
            idFrom = stoi(decrypted.substr(0, index));
            idTo = stoi(decrypted.substr(index + 1, decrypted.length()));
        }
        catch (exception& e) {
            cout << "Invalid account IDs" << endl;
            request.reply(status_codes::BadRequest, L"Invalid account ID sent. Please try again.");
        }
        if (idTo == 1) {
            cout << "Attempted sending of money from account " << idFrom << "to the admin account." << endl << endl;
            request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
        }
        cout << "ID to: " << idTo << endl;
        if (idTo == idFrom) {
            cout << "Attempted sending of money from account " << idFrom << " to itself." << endl << endl;
            request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
        }
        else {
            Account* accFrom = dat->getAccount(idFrom, *context);
            Account* accTo = dat->getAccount(idTo, *context);
            if (accTo == nullptr) {
                wcout << "Attempt to send money to invalid account with ID " << idTo << "." << endl << endl;
                request.reply(status_codes::BadRequest, L"Invalid recipient account selected. You cannot choose this account as a recipient.");
            }
            else {
                wstring amount = request.extract_utf16string().get();
                double am = 0.0;
                try {
                    double am = stod(aesDecrypt(amount, aesKey, iv));
                }
                catch (exception& e) {
                    cout << "Unable to read the amount desired to be sent." << endl;
                    request.reply(status_codes::BadRequest, L"Invalid amount to be sent.");
                }
                cout << "Amount to transfer: " << am << endl;
                if (loggedIn.contains(idFrom)) {
                    if (loggedIn.at(idFrom).compare(request.get_remote_address()) == 0) {
                        seal::CKKSEncoder encoder(*context);
                        seal::SecretKey secret_key;
                        string keyAddress = accFrom->getKeyAddress();
                        cout << "Key address: " << keyAddress << endl;
                        ifstream keyIn(keyAddress, std::ios::binary);
                        secret_key.load(*context, keyIn);
                        keyIn.close();
                        seal::Encryptor encryptor(*context, secret_key);
                        seal::Decryptor decryptor(*context, secret_key);
                        seal::Plaintext plaintext;
                        seal::Ciphertext ciphertext;
                        double scale = pow(2, 20);
                        encoder.encode(am, scale, plaintext);
                        encryptor.encrypt_symmetric(plaintext, ciphertext);
                        time_t nowTime = time(nullptr);
                        cout << nowTime << endl;
                        transactionID = dat->getTransactionID() + 1;
                        wstring fileName = to_wstring(idFrom) + L"'" + to_wstring(idTo) + L"'" + to_wstring(transactionID) + L".txt";
                        std::ofstream outFile(fileName, std::ios::binary);
                        ciphertext.save(outFile);
                        outFile.close();
                        wstring balAddress = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress());
                        vector<double> res;
                        getAmount(balAddress, ciphertext);
                        remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
                        decryptor.decrypt(ciphertext, plaintext);
                        encoder.decode(plaintext, res);
                        cout << fixed << setprecision(2) << res[0] - am << endl;
                        if (am <= res[0] + accFrom->getOverdraft() && am > 0.00999) {
                            http_client client2(L"http://ec2-52-90-156-60.compute-1.amazonaws.com:8081/transfer");
                            auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
                            wstring toSendFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accFrom->getBalanceAddress()) + L"," + std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(accTo->getBalanceAddress()) + L"," + fileName;
                            auto response = client2.request(methods::PUT, toSendFile, f.streambuf());
                            wcout << response.get().status_code();
                            dat->logTransaction(accFrom, accTo, nowTime, transactionID);
                            am = -am;
                            encoder.encode(am, scale, plaintext);
                            encryptor.encrypt_symmetric(plaintext, ciphertext);
                            fileName = to_wstring(idTo) + L"'" + to_wstring(idFrom) + L"'" + to_wstring(transactionID) + L".txt";
                            ofstream outFile2(fileName, std::ios::binary);
                            ciphertext.save(outFile2);
                            outFile2.close();
                            f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
                            response = client2.request(methods::POST, fileName, f.streambuf());
                            wcout << response.get().extract_utf16string().get() << endl;
                            cout << "Transferred successful from " << idFrom << " to " << idTo << " for amount " << (char)156 << -am << "." << endl << endl;
                            delete[] aesKey;
                            delete[] iv;
                            request.reply(status_codes::OK);
                        }
                        else {
                            cout << "Attempted transaction with invalid input." << endl << endl;
                            request.reply(status_codes::BadRequest, L"Invalid input. Please try again.");
                        }
                    }
                    else {
                        wcout << "Attempted access to account " << idFrom << " from a different IP." << endl << endl;
                        request.reply(status_codes::Conflict);
                    }
                }
                else {
                    wcout << "Attempted access to logged out account " << idFrom << "." << endl << endl;
                    request.reply(status_codes::Conflict);
                }
            }
        }
    }
    catch (exception& e) {
        string errmsg = e.what();
        if (errmsg.compare("invalid stoi argument") == 0 || errmsg.compare("invalid stod argument") == 0) {
            request.reply(status_codes::BadRequest);
            wcout << "Invalid input in transaction" << endl << endl;
        }
        else {
            cout << "Internal error occurred." << endl;
            cout << e.what() << endl << endl;;
            request.reply(status_codes::InternalError);
        }
    }
}

void serverBalance(http_request request) {
    try {
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        wcout << idTo << endl;
        string idToCheck = aesDecrypt(idTo, aesKey, iv);
        cout << "Request for balance from: " << idToCheck << endl;
        int id = 0;
        try {
            id = stoi(idToCheck);
        }
        catch (exception& e) {
            cout << "Stoi error on id." << endl;
            request.reply(status_codes::BadRequest);
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                Account* account = dat->getAccount(id, *context);
                cout << account->getBalanceAddress() << endl;
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
                getAmount(balAddress, ciphertext);
                decryptor.decrypt(ciphertext, plaintext);
                encoder.decode(plaintext, result);
                string toEncrypt = to_string(result[0]);
                wstring toSend = aesEncrypt(toEncrypt, aesKey, iv);
                request.reply(status_codes::OK, toSend);
                remove(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(balAddress).c_str());
            }
            else {
                wcout << "Attempted access to account " << idTo << " from a different IP." << endl << endl;
                request._reply_if_not_already(status_codes::Forbidden);
            }
        }
        else {
            wcout << "Attempted access to logged out account " << idTo << "." << endl << endl;
            request._reply_if_not_already(status_codes::Forbidden);
        }
    }
    catch (exception& e) {
        wcout << "Internal error occurred:" << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
    }
}

void serverHistory(http_request request) {
    try {
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        int id = 0;
        try {
            id = stoi(aesDecrypt(idTo, aesKey, iv));
        }
        catch (exception& e) {
            request.reply(status_codes::BadRequest);
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                TransactionList* transactions = dat->getTransactions(id, *context);
                std::string details = "";
                if (transactions == nullptr) {
                    details = "No transactions have occurred on this account.";
                    wstring toSend = aesEncrypt(details, aesKey, iv);
                    request.reply(status_codes::OK, toSend);
                }
                else {
                    for (Transaction* transaction : transactions->getTransactions()) {
                        cout << "Amount address: " << transaction->getAmount() << endl;
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
                        getAmount(balAddress, ciphertext);
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
                    cout << "Done!" << endl;
                    request.reply(status_codes::OK, toSend);
                }
            }
        }
        request._reply_if_not_already(status_codes::Forbidden);
    }
    catch (exception& e) {
        cout << "Internal error occurred: " << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
    }
}

void serverDebits(http_request request) {
    try {
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        wstring idTo = request.relative_uri().to_string();
        idTo = idTo.substr(1, idTo.length());
        idTo = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(aesDecrypt(idTo, aesKey, iv));
        int id = 0;
        try {
            id = stoi(idTo);
        }
        catch (exception& e) {
            wcout << "Invalid stoi request on id " << idTo << endl;
            request.reply(status_codes::BadRequest);
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
                    details = "No debits exist on this account, mate.\n";
                }
                wstring toSend = aesEncrypt(details, aesKey, iv);
                request.reply(status_codes::OK, toSend);
            }
        }
        request._reply_if_not_already(status_codes::Forbidden);
    }
    catch (exception& e) {
        cout << "Internal error occurred: " << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
    }
}

void serverAddDebits(http_request request) {
    try {
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        wstring idFrom = request.relative_uri().to_string();
        idFrom = idFrom.substr(1, idFrom.length());

        int id;
        try {
            id = stoi(aesDecrypt(idFrom, aesKey, iv));
        }
        catch (exception& e) {
            cout << "Bad account ID conversion" << endl;
            request._reply_if_not_already(status_codes::BadRequest);
        }
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                Account* from = dat->getAccount(id, *context);
                wstring details = request.extract_utf16string().get();
                string decrypted = aesDecrypt(details, aesKey, iv);
                details = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(decrypted);
                wcout << L"Detail:" << details << endl;
                int index = details.find_first_of(L",");
                wstring idString = details.substr(0, index);
                details = details.substr(index + 1, details.length());
                index = details.find_first_of(L",");
                wstring regularity = details.substr(0, index);
                details = details.substr(index + 1, details.length());
                wstring amountString = details;
                wcout << "ID: " << idString << endl;
                wcout << "Regularity: " << regularity << endl;
                wcout << "Amount: " << amountString << endl;
                Account* to = nullptr;
                try {
                    to = dat->getAccount(stoi(idString), *context);
                }
                catch (exception& e) {
                    cout << "Bad account ID conversion for send to request from account " << id << endl << endl;
                    request._reply_if_not_already(status_codes::BadRequest);
                }
                cout << "About to check against debits" << endl;
                auto debitList = dat->queryDebits(*context);
                bool exists = false;
                if (debitList != nullptr) {
                    for (auto d : debitList->getDebits()) {
                        if (d->getTo()->getId() == to->getId()) {
                            exists = true;
                            break;
                        }
                    }
                }
                if (to == nullptr) {
                    cout << "Attempting to send money to an invalid account." << endl;
                    request._reply_if_not_already(status_codes::BadRequest);
                }
                else if (from->getId() == to->getId()) {
                    cout << "User number " << id << " attempted to create a direct debit to themselves." << endl << endl;
                    request._reply_if_not_already(status_codes::BadRequest);
                }
                else {
                    cout << "About to create cron" << endl;
                    string regString = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(regularity);
                    cout << "Creating with expression: " << regString << endl << endl;
                    cron::cronexpr expression;
                    bool validCron = true;
                    try {
                        expression = cron::make_cron(regString);
                    }
                    catch (exception& e) {
                        cout << "User " << id << " sent a bad cron expression." << endl << endl;
                        request._reply_if_not_already(status_codes::BadRequest);
                        validCron = false;
                    }
                    if (validCron) {
                        seal::SecretKey secret_key;
                        ifstream keyIn(from->getKeyAddress(), std::ios::binary);
                        secret_key.load(*context, keyIn);
                        keyIn.close();
                        cout << "About to make direct debit pointer" << endl;
                        seal::Encryptor encryptor(*context, secret_key);
                        seal::CKKSEncoder encoder(*context);
                        cout << "Encryption stuff made" << endl;
                        double amount = 0.0;
                        try {
                            amount = stod(amountString);
                            cout << "Amount: " << amount << endl;
                        }
                        catch (exception& e) {
                            cout << "Bad stod conversion on amount string from user " << id << endl << endl;
                            request._reply_if_not_already(status_codes::BadRequest);
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
                            http_client client(L"http://ec2-52-90-156-60.compute-1.amazonaws.com:8081/debits");
                            auto f = file_stream<char>::open_istream(toSend, std::ios::binary).get();
                            auto response = client.request(methods::POST, toSend, f.streambuf());
                            if (response.get().status_code() == status_codes::OK) {
                                DirectDebit* debit = new DirectDebit(0, from, to, address, expression, nowTime);
                                dat->addDebit(debit, regString, *context, *params);
                                cout << "Direct debit added to account " << to_string(id) << endl << endl;
                                request._reply_if_not_already(status_codes::OK);
                            }
                            request._reply_if_not_already(status_codes::InternalError);
                        }
                    }
                }
            }
        }
        request.reply(status_codes::Forbidden);
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl << endl;
        request.reply(status_codes::InternalError);
    }
}

void serverRemoveDebit(http_request request) {
    try {
        unsigned char* aesKey = ipsAndKeys.at(request.get_remote_address());
        unsigned char* iv = ipsAndIvs.at(request.get_remote_address());
        wstring idFrom = request.relative_uri().to_string();
        idFrom = idFrom.substr(1, idFrom.length());
        idFrom = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(aesDecrypt(idFrom, aesKey, iv));
        wcout << idFrom << endl;
        int id = 0;
        try {
            id = stoi(idFrom);
        }
        catch (exception& e) {
            cout << "Invalid stoi from id" << endl;
            request.reply(status_codes::BadRequest);
        }
        cout << id << endl;
        if (loggedIn.contains(id)) {
            if (loggedIn.at(id).compare(request.get_remote_address()) == 0) {
                cout << "We are verified" << endl;
                Account* acc = dat->getAccount(id, *context);
                wstring debitId = request.extract_utf16string().get();
                int deb = 0;
                try {
                    deb = stoi(aesDecrypt(debitId, aesKey, iv));
                }
                catch (exception& e) {
                    cout << "Invalid stoi conversion on direct debit ID" << endl << endl;
                    cout << "Invalid stoi conversion on direct debit ID" << endl << endl;
                    request.reply(status_codes::BadRequest);
                }
                cout << "Debit ID: ";
                cout << deb << endl;
                DebitList* debits = dat->queryDebits(*context);
                if (debits == nullptr) {
                    request.reply(status_codes::NotFound);
                }
                else {
                    for (DirectDebit* d : debits->getDebits())
                    {
                        if (d->getId() == deb) {
                            if (d->getFrom()->getId() == id) {
                                dat->removeDebit(d->getId());
                                cout << "Removed from DB" << endl;
                                std::string address = d->getAmountAddress();
                                wstring add = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(address);
                                cout << address << endl;

                                http_client client(L"http://ec2-52-90-156-60.compute-1.amazonaws.com:8081/debits");
                                auto response = client.request(methods::DEL, add);
                                debits->removeDebit(d);
                                remove(address.c_str());
                                request._reply_if_not_already(status_codes::OK);
                                break;
                            }
                        }
                    }
                    request._reply_if_not_already(status_codes::NotFound);
                }
            }
        }
        request._reply_if_not_already(status_codes::Forbidden);
    }
    catch (exception& e) {
        cout << "Internal error occurred:" << endl;
        cout << e.what() << endl;
        request.reply(status_codes::InternalError);
    }
}

void replyToHeartbeat(http_request request) {
    wcout << L"Heartbeat received from " << request.get_remote_address() << endl;
    heartbeats.at(request.get_remote_address()) = time(nullptr);
    request.reply(status_codes::OK);
}

void checkHeartbeats() {
    while (true) {
        for (auto const& [ip, lastHeartbeat] : heartbeats) {
            wcout << ip << endl;
            if (lastHeartbeat < time(nullptr) - 15) {
                heartbeats.erase(ip);
                ipsAndIvs.erase(ip);
                ipsAndKeys.erase(ip);
                cout << "Forcibly logging out unresponsive account" << endl;
                for (auto const& [id, ip2] : loggedIn) {
                    cout << id << endl;
                    wcout << ip2 << endl;
                    cout << ip2.compare(ip) << endl;
                    if (ip2.compare(ip) == 0) {
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
}

int main()
{
    std::thread heartbeatThread(checkHeartbeats);

        try {
            ifstream getPri(PRI_KEY_FILE);
            while (!getPri.eof()) {
                priKey += getPri.get();
            }
            getPri.close();
            ifstream getPub(PUB_KEY_FILE);
            while (!getPub.eof()) {
                pubKey += getPub.get();
            }

            cout << priKey << endl;
            cout << pubKey << endl;

            loadCKKSParams(*params);
            do {
                seal::SEALContext con(*params);
                context = new seal::SEALContext(con);
            } while (false);
            dat->connectToDB();
            transactionID = dat->getTransactionID();
            http_listener loginListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/login");
            loginListener.support(methods::PUT, serverLogin);
            loginListener.support(methods::DEL, serverLogout);

            http_listener transactionListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/transfer");
            transactionListener.support(methods::POST, serverTransfer);

            http_listener balanceListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/balance");
            transactionListener.support(methods::GET, serverBalance);

            http_listener historyListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/history");
            historyListener.support(methods::GET, serverHistory);

            http_listener debitListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/debits");
            debitListener.support(methods::GET, serverDebits);
            debitListener.support(methods::POST, serverAddDebits);
            debitListener.support(methods::DEL, serverRemoveDebit);

            http_listener keyListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/requestkey");
            keyListener.support(methods::POST, sendKeys);

            http_listener heartbeatListener(L"http://ec2-3-88-37-43.compute-1.amazonaws.com:8080/heartbeat");
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
}