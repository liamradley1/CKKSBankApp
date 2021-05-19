//#include <seal/seal.h>
//#include "TCPHandler.h"
//#include "Account.h"
//#include <iostream>
//#include <cstdio>
//
//int clientLoginSequence(TCPHandler handler, SOCKET& ConnectSocket, SOCKET& ListenSocket, SOCKET& ServerSocket) {
//    int id = 0;
//    std::cout << "Connection established! Enter your account ID, or type 0 to exit :" << std::endl;
//    std::cout << "Account ID: " << std::flush;
//    std::cin >> id;
//    if (id == 0) {
//        handler.transmitInt(ConnectSocket, id);
//        return -1;
//    }
//    handler.transmitInt(ConnectSocket, id);
//    int valid = handler.receiveInt(ServerSocket);
//    if (valid == 0) {
//        std::cout << "Invalid user ID." << std::endl;
//        return -1;
//    }
//    std::cout << "Please enter your pin: " << std::endl;
//    std::string pin;
//    std::getline(std::cin, pin);
//    std::getline(std::cin, pin);
//    std::hash<int> hash;
//    size_t hashed;
//    hashed = hash(std::stoi(pin));
//    const char* toSend = std::to_string(hashed).c_str();
//    std::cout << pin << ", " << hashed << std::endl;
//    handler.transmitInt(ConnectSocket, strlen(toSend));
//    handler.transmitCharArray(ConnectSocket, toSend, strlen(toSend));
//    valid = handler.receiveInt(ServerSocket);
//    if (valid == 1) {
//        std::cout << "Logged in!" << std::endl;
//        return id;
//    }
//    else {
//        std::cout << "Wrong pin." << std::endl;
//        return -1;
//    }
//}
//
//double* receiveBalance(TCPHandler handler, SOCKET ServerSocket, seal::SEALContext context, seal::SecretKey secret_key) {
//    double* bal = new double;
//    try {
//        const char* fileAddress = handler.receiveFile(ServerSocket);
//        std::ifstream inFile(fileAddress, std::ios::binary);
//        seal::Ciphertext c;
//        seal::Plaintext p;
//        seal::CKKSEncoder encoder(context);
//        seal::Decryptor decryptor(context, secret_key);
//        std::vector<double> balVec;
//        c.load(context, inFile);
//        decryptor.decrypt(c, p);
//        encoder.decode(p, balVec);
//        *bal = balVec[0];
//    }
//    catch (std::exception& e) {
//        bal = nullptr;
//        std::cout << e.what() << std::endl;
//    }
//    return bal;
//}
//
//void loadCKKSParams(seal::EncryptionParameters& params, seal::PublicKey& public_key) {
//    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
//    params.load(paramsFileIn);
//    paramsFileIn.close();
//    seal::SEALContext context(params);
//    std::ifstream pubFileIn("publicKeyCKKS.pem", std::ios::binary);
//    public_key.load(context, pubFileIn);
//    pubFileIn.close();
//}
//
//bool clientTransferSequence(TCPHandler handler, SOCKET& ConnectSocket, SOCKET& ServerSocket, seal::SEALContext context, seal::PublicKey& public_key, int loggedId) {
//    try {
//        std::cout << "Input the ID of the account you wish to transfer to: " << std::endl;
//        std::cout << "Account ID: " << std::flush;
//        int id;
//        std::string input;
//        std::getline(std::cin, input);
//        id = stoi(input);
//        handler.transmitInt(ConnectSocket, id);
//        if (handler.receiveInt(ServerSocket) != 0) {
//            std::cout << "This account does not exist. Please try again." << std::endl;
//        }
//        else {
//            std::ifstream inFile("privateKey.pem", std::ios::binary);
//            seal::SecretKey secret_key;
//            secret_key.load(context, inFile);
//            inFile.close();
//            seal::Decryptor decryptor(context, secret_key);
//            seal::CKKSEncoder encoder(context);
//            seal::Encryptor encryptor(context, public_key);
//            seal::Plaintext p;
//            seal::Ciphertext c;
//            double amount;
//            // Keep running dialogue until a valid amount is input.
//            while (true) {
//                std::cout << "Input the amount of money you would like to send. Send '0' if you want to go back." << std::endl;
//                std::cout << "Amount: " << (char)156 << std::flush;
//                std::string amountString;
//                std::getline(std::cin, amountString);
//                amount = stod(amountString);
//                if (amount == 0.0) {
//                    // Tell the server you intend to head back to the menu.
//                    handler.transmitInt(ConnectSocket, 0);
//                    //clientMenuSequence(handler, ConnectSocket, ServerSocket, context, public_key, loggedId);
//                    return false;
//                    break;
//                }
//                // Tell the server you're going to carry on with the process.
//                handler.transmitInt(ConnectSocket, 1);
//                int overdraft = handler.receiveInt(ServerSocket);
//                double* bal;
//                // Keep requesting balance until reading is successful. This ensures the most up to date version of one's balance possible is used for verification.
//                while (true) {
//                    try {
//                        bal = receiveBalance(handler, ServerSocket, context, secret_key);
//                        if (bal != nullptr) {
//                            // Tell the server that everything is ok and the balance has been correctly received.
//                            handler.transmitInt(ConnectSocket, 0);
//                            break;
//                        }
//                        else {
//                            // Tell the server there was an error and ask it to send again.
//                            handler.transmitInt(ConnectSocket, 1);
//                        }
//                    }
//                    catch (std::exception& e) {
//                        std::cout << e.what() << std::endl;
//                    }
//                }
//                // Validate the input of the user against the balance before sending.
//                if (amount >= 0.01 && *bal - amount + overdraft >= 0.0) {
//                    handler.transmitInt(ConnectSocket, 0);
//                    break;
//                }
//                else {
//                    std::cout << "Invalid amount. Please try again." << std::endl;
//                    handler.transmitInt(ConnectSocket, 1);
//                }
//            }
//            double scale = pow(2, 20);
//            encoder.encode(amount, scale, p);
//            encryptor.encrypt(p, c);
//
//            std::string fileName = std::to_string(loggedId) + "'" + std::to_string(id) + "'" + std::to_string(time(nullptr)) + ".txt";
//            std::ofstream outFile(fileName, std::ios::binary);
//            c.save(outFile);
//            outFile.close();
//            std::cout << fileName << " sending" << std::endl;
//            handler.transmitFile(ConnectSocket, fileName);
//            std::cout << fileName << " sent!" << std::endl;
//            remove(fileName.c_str());
//            std::cout << strerror(errno) << std::endl;
//            int done = handler.receiveInt(ServerSocket);
//            if (done == 0) {
//                std::cout << "Successful transaction!" << std::endl;
//                return true;
//            }
//            else {
//                std::cout << "Transaction failed. Please try again." << std::endl;
//                return false;
//            }
//        }
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//        return false;
//    }
//}
//
//bool clientBalanceSequence(TCPHandler handler, SOCKET ConnectSocket, SOCKET ServerSocket, seal::SEALContext context) {
//    try {
//        const char* fileName = handler.receiveFile(ServerSocket);
//        std::cout << fileName << std::endl;
//        seal::SecretKey secret_key;
//        std::ifstream inFile("privateKeyCKKS.pem", std::ios::binary);
//        secret_key.load(context, inFile);
//        inFile.close();
//        std::ifstream inFile2(fileName, std::ios::binary);
//        seal::Ciphertext c;
//        c.load(context, inFile2);
//        inFile2.close();
//        seal::Decryptor decryptor(context, secret_key);
//        seal::CKKSEncoder encoder(context);
//        seal::Plaintext p;
//        std::vector<double> ans;
//        decryptor.decrypt(c, p);
//        encoder.decode(p, ans);
//        std::cout << "Your balance is : " << char(156) << std::fixed << std::setprecision(2) << ans[0] << std::endl;
//        handler.transmitInt(ConnectSocket, 0);
//        if (remove(fileName) != 0) {
//            std::cout << strerror(errno) << std::endl;
//        }
//        return true;
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//        std::cout << "Error when receiving balance. Trying again!" << std::endl;
//        handler.transmitInt(ConnectSocket, 1);
//        return clientBalanceSequence(handler, ConnectSocket, ServerSocket, context);
//    }
//}
//
//bool clientHistorySequence(TCPHandler handler, SOCKET ConnectSocket, SOCKET ServerSocket, seal::SEALContext context, int loggedId) {
//    try {
//        std::cout << "WIP" << std::endl;
//        return true;
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//        return clientHistorySequence(handler, ConnectSocket, ServerSocket, context, loggedId);
//    }
//}
//
//bool clientMenuSequence(TCPHandler handler, SOCKET ConnectSocket, SOCKET ServerSocket, seal::SEALContext context, seal::PublicKey public_key, int loggedId) {
//    while (true) {
//        try {
//            std::cout << "1: Make a transfer.\n2: Check balance.\n3: Check transaction history.\n4: Add or remove direct debits.\n5: Log out." << std::endl;
//            std::cout << "Choice: " << std::flush;
//            int choice;
//            std::string input;
//            std::getline(std::cin, input);
//            choice = stoi(input);
//            if (choice > 0 && choice < 6) {
//                handler.transmitInt(ConnectSocket, choice);
//            }
//            switch (choice) {
//            case 1:
//                clientTransferSequence(handler, ConnectSocket, ServerSocket, context, public_key, loggedId);
//                break;
//            case 2:
//                clientBalanceSequence(handler, ConnectSocket, ServerSocket, context);
//                break;
//            case 3:
//                clientHistorySequence(handler, ConnectSocket, ServerSocket, context, loggedId);
//                break;
//            case 4:
//                break;
//            case 5:
//                std::cout << "Logging out..." << std::endl;
//                return true;
//            default:
//                std::cout << "Invalid choice. Please try again." << std::endl;
//                break;
//            }
//        }
//        catch (std::exception& e) {
//            std::cout << e.what() << std::endl;
//        }
//    }
//}
//
//int __cdecl main(int argc, char** argv)
//{
//    try {
//        seal::EncryptionParameters params;
//        seal::PublicKey public_key;
//        loadCKKSParams(params, public_key);
//        seal::SEALContext context(params);
//        while (true) {
//            TCPHandler handler;
//            SOCKET ConnectSocket = INVALID_SOCKET;
//            SOCKET ListenSocket = INVALID_SOCKET;
//            SOCKET ServerSocket = INVALID_SOCKET;
//            handler.initiateSendConnection(DEFAULT_SEND_PORT, ConnectSocket);
//            handler.initiateListenConnection(DEFAULT_RECEIVE_PORT, ServerSocket, ListenSocket);
//            int id = clientLoginSequence(handler, ConnectSocket, ListenSocket, ServerSocket);
//            if (id != -1) {
//                //clientMenuSequence(handler, ConnectSocket, ServerSocket, context, public_key, id);
//            }
//            closesocket(ConnectSocket);
//            closesocket(ListenSocket);
//            closesocket(ServerSocket);
//            if (id == -1) {
//                return 0;
//            }
//        }
//    }
//    catch (std::exception& e) {
//        std::cout << e.what() << std::endl;
//        return 1;
//    }
//
//    //TCPHandler handler;
//    //SOCKET ConnectSocket = INVALID_SOCKET;
//    //SOCKET ListenSocket = INVALID_SOCKET;
//    //SOCKET ServerSocket = INVALID_SOCKET;
//    //handler.initiateSendConnection(DEFAULT_SEND_PORT, ConnectSocket);
//    //handler.initiateListenConnection(DEFAULT_RECEIVE_PORT, ServerSocket, ListenSocket);
//    //handler.receiveFile(ServerSocket);
//
//
//    //try {
//    //    seal::EncryptionParameters params;
//    //    seal::PublicKey public_key;
//    //    loadCKKSParams(params, public_key);
//    //    seal::SEALContext context(params);
//    //    seal::SecretKey secret_key;
//    //    std::ifstream inFile("privateKeyCKKS.pem", std::ios::binary);
//    //    secret_key.load(context, inFile);
//    //    inFile.close();
//    //    std::ifstream inFile2("testCipher1.txt", std::ios::binary);
//    //    seal::CKKSEncoder encoder(context);
//    //    seal::Decryptor decryptor(context, secret_key);
//    //    seal::Ciphertext c;
//    //    c.load(context, inFile2);
//    //    seal::Plaintext p;
//    //    decryptor.decrypt(c, p);
//    //    std::vector<double> ans;
//    //    encoder.decode(p, ans);
//    //    std::cout << ans[0] << std::endl;
//    //}
//    //catch (std::exception& e) {
//    //    std::cout << e.what() << std::endl;
//    //}
//}

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/uri.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <codecvt>
#include <locale>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;
using namespace web;
using namespace web::http;
using namespace web::http::client;

using namespace concurrency::streams;

static wstring loggedID = L"";

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

web::http::status_code getFile(std::wstring endpoint, std::wstring fileName) {
    http_client client(endpoint);
    auto response = client.request(methods::GET, fileName).get();
    if (response.status_code() == status_codes::OK) {
        string result;
        auto buf = response.body().streambuf();
        while (!buf.is_eof()) {
            result += buf.sbumpc();
        }
        std::ofstream outFile(fileName);
        outFile << result;
    }
    return response.status_code();
}

web::http::status_code putFile(std::wstring endpoint, std::wstring fileName) {
    if (!filesystem::exists(fileName)) {
        return status_codes::BadRequest;
    }
    auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
    http_client client(endpoint);
    auto response = client.request(methods::PUT, fileName, f.streambuf()).get();
    f.close();
    return response.status_code();
}

web::http::status_code postFile(std::wstring endpoint, std::wstring fileName) {
    if (!filesystem::exists(fileName)) {
        return status_codes::BadRequest;
    }
    auto f = file_stream<char>::open_istream(fileName, std::ios::binary).get();
    http_client client(endpoint);
    auto response = client.request(methods::POST, fileName, f.streambuf()).get();
    f.close();
    return response.status_code();
}

web::http::status_code delFile(std::wstring endpoint, std::wstring fileName) {
    http_client client(endpoint);
    auto response = client.request(methods::DEL, fileName).get();
    return response.status_code();
}

web::http::status_code sendLogin(wstring id, wstring pin) {
    http_client client(L"http://localhost:8080/login");
    auto response = client.request(methods::PUT, id, pin).get();
    if (response.status_code() == status_codes::OK) {
        loggedID = id;
        cout << "Logged in!" << endl;
    }
    else if (response.status_code() == status_codes::BadRequest) {
        cout << "Invalid account id." << endl;
    }
    else if (response.status_code() == status_codes::NotAcceptable) {
        cout << "Invalid pin." << endl;
    }
    else if (response.status_code() == status_codes::Forbidden) {
        cout << "You have entered your pin wrong too many times!" << endl;
        exit(1);
    }
    else if (response.status_code() == status_codes::Conflict) {
        cout << "Someone else is logged in right now!" << endl;
    }
    else {
        cout << "Something went wrong. Please try again." << endl;
    }
    cout << flush;
    return response.status_code();
}

// TO-DO: Add logged in account number to request
status_code sendTransfer() {
    wstring accountId;
    wstring amount;
    cout << "Which account would you like to send to?" << endl;
    getline(wcin, accountId);
    cout << "How much would you like to send?" << endl;
    cout << "Amount: " << (char)156 << flush;
    getline(wcin, amount);
    http_client client(L"http://localhost:8080/transfer");
    auto response = client.request(methods::POST, loggedID+L","+accountId, amount).get();
    if (response.status_code() == status_codes::OK) {
        cout << "Transfer successful!" << endl;
    }
    else if (response.status_code() == status_codes::BadRequest) {
        cout << "Invalid account ID." << endl;
    }
    else if (response.status_code() == status_codes::Conflict) {
        cout << "Nobody is logged in." << endl;
    }
    else if (response.status_code() == status_codes::Forbidden) {
        cout << "You do not have enough money in this account to complete the transaction." << endl;
    }
    else {
        cout << "Something went wrong on our end." << endl;
    }
    return response.status_code();
}

status_code checkBalance() {
    http_client client(L"http://localhost:8080/transfer");
    auto response = client.request(methods::GET, loggedID);
    double balance = stod(response.get().extract_utf16string().get());
    cout << "Balance: " << (char)156 << setprecision(2) << fixed << balance << endl << endl;
    return response.get().status_code();
}

status_code checkHistory() {
    return status_codes::OK;
    http_client client(L"http://localhost:8080/history");
    auto response = client.request(methods::GET, loggedID);

}

status_code debitMenu() {
    return status_codes::OK;
}

status_code sendLogout() {
    http_client client(L"http://localhost:8080/login");
    auto response = client.request(methods::DEL, loggedID).get();
    if (response.status_code() == status_codes::OK) {
        cout << "Logged out!" << endl;
    }
    return response.status_code();
}

void aesTest() {
    /*
 * Set up the key and iv. Do I need to say to not hard code these in a
 * real application? :-)
 */

  /* A 256 bit key */
 unsigned char* key = (unsigned char*)"01234567890123456789012345678901";

 /* A 128 bit IV */
 unsigned char* iv = (unsigned char*)"0123456789012345";

 /* Message to be encrypted */
 unsigned char * plaintext = new unsigned char[128];
 string p;
 cout << "Enter the message you wish to send." << endl;
 getline(cin, p);
 plaintext = reinterpret_cast<unsigned char*>(const_cast<char*>(p.c_str()));
 unsigned char ciphertext[128];
 int ciphertext_len, plaintext_len;
 plaintext_len = p.length();
 /* Encrypt the plaintext */
 ciphertext_len = encrypt(plaintext, strlen((char*)plaintext), key, iv,
     ciphertext);

 http_client client(L"http://localhost:8080/test");
 string s = reinterpret_cast<const char*>(ciphertext);
 try {
     std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
     wstring s1 = L"";
     for (int i = 0; i < s.length(); ++i) {
         s1.push_back(btowc(s.c_str()[i]));
     }
     wcout << "Ciphertext to send: " << s1 << endl;
     cout << "Plaintext expected: " << plaintext << endl;
     wstring fragment = to_wstring(plaintext_len) + L"," + to_wstring(ciphertext_len);
     wcout << fragment << endl;
     auto response = client.request(methods::PUT, to_wstring(plaintext_len)+L","+to_wstring(ciphertext_len), s1).get();
     cout << response.status_code() << endl;
 }
 catch (exception& e) {
     cout << e.what() << endl;
 }
}

int main()
{
    while (true) {
        status_code code;
        do {
            cout << "Enter your account id." << endl;
            wstring id;
            string pin;
            cout << "id: " << flush;
            getline(wcin, id);
            cout << "pin: " << flush;
            getline(cin, pin);
            std::hash<int> hash;
            size_t hashed;
            hashed = hash(std::stoi(pin));
            pin = to_string(hashed);
            cout << hashed << endl;
            wstring pinToSend = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(pin);
            wcout << pinToSend << endl;
            code = sendLogin(id, pinToSend);
            if (code == status_codes::OK) {
                loggedID = id;
            }
        } while (code != status_codes::OK);
        int in = 0;
        do {
            cout << "What do you want to do?" << endl;
            std::cout << "1: Make a transfer.\n2: Check balance.\n3: Check transaction history.\n4: Add or remove direct debits.\n5: Log out." << std::endl;
            std::cout << "Choice: " << std::flush;
            std::string input;
            std::getline(std::cin, input);
            in = stoi(input);
            switch (in) {
            case 1:
                sendTransfer();
                break;
            case 2:
                checkBalance();
                break;
            case 3:
                checkHistory();
                break;
            case 4:
                debitMenu();
                break;
            case 5:
                std::cout << "Logging out..." << std::endl;
                sendLogout();
                return true;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
            }
        } while (in != 5);
    }
}