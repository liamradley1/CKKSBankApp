#include <iostream>
#include <fstream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <chrono>
#include <seal/seal.h>
#include <iomanip>

#define PUB_KEY_FILE "RSAPub.pem"
#define PRI_KEY_FILE "RSAPri.pem"

using namespace std;

// Generates sessional AES keys and IVs
void GenerateAESKey(unsigned char* outAESKey, unsigned char* outAESIv) {
    unsigned char* key = new unsigned char[256];
    unsigned char* iv = new unsigned char[256 / 2];
    if (!RAND_bytes(outAESKey, 256)) {
        cout << "Error creating key." << endl;
    }
    if (!RAND_bytes(outAESIv, 256 / 2)) {
        cout << "Error creating IV." << endl;
    }
}
// Error handling function for AES
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
}

// Encrypts an unsigned char* into another unsigned char* using OpenSSL
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext)
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

// Decrypts an unsigned char* into another unsigned char* using OpenSSL
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
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

// Encrypts a string into a wstring for sending. Uses the above encrypt function
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

// Decrypts a wstring into a string. uses the above decrypt function
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

// Generate an RSA keypair and stores them in predetermined files
void GenerateRSAKey(std::string& out_pub_key, std::string& out_pri_key, int KEY_LENGTH)
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

// Encrypts a string with the private RSA key
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

// Decrypts a string with the public RSA key
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

// Encrypts a string with the public RSA key
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
        return "";
    }
}

// Decrypts a string with the private RSA key
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
            pos += key_len;
        }
    }
    // release memory  
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}

// Loads the CKKS encryption parameters from the paramsCKKS.txt file
void loadCKKSParams(seal::EncryptionParameters& params) {
    std::ifstream paramsFileIn("paramsCKKS.txt", std::ios::binary);
    params.load(paramsFileIn);
    paramsFileIn.close();
}


// Performs the addition benchmarking test for RSA
int rsaAddBenchmarking(int iterations, int keySize) {
    int rsaAvg = 0;
    string pubKey;
    string priKey;
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateRSAKey(pubKey, priKey, keySize);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        string strAmount = to_string(amount);
        string strToAdd = to_string(toAdd);
        string encAmount = RsaPubEncrypt(strAmount, pubKey);
        string encToAdd = RsaPubEncrypt(strToAdd, pubKey);
        auto beginTime = chrono::high_resolution_clock::now();
        string decAmount = RsaPriDecrypt(encAmount, priKey);
        string decToAdd = RsaPriDecrypt(encToAdd, priKey);
        amount = stod(decAmount);
        toAdd = stod(decToAdd);
        amount += toAdd;
        strAmount = to_string(amount);
        encAmount = RsaPubEncrypt(strAmount, pubKey);
        auto endTime = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(endTime - beginTime).count();
        rsaAvg += ms;
    }
    rsaAvg /= iterations;
    cout << "Average time for RSA on " << keySize << " bits: " << rsaAvg << " microseconds" << endl;
    return rsaAvg;
}

// Performs the addition benchmarking test for AES
int aesAddBenchmarking(int iterations) {
    int keySize = 256;
    int aesAvg = 0;
    unsigned char* aesKey = new unsigned char[keySize];
    unsigned char* iv = new unsigned char[keySize / 2];
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        string strAmount = to_string(amount);
        string strToAdd = to_string(toAdd);
        wstring encAmount = aesEncrypt(strAmount, aesKey, iv);
        wstring encToAdd = aesEncrypt(strToAdd, aesKey, iv);
        auto beginTime = chrono::high_resolution_clock::now();
        string decAmount = aesDecrypt(encAmount, aesKey, iv);
        string decToAdd = aesDecrypt(encToAdd, aesKey, iv);
        amount = stod(decAmount);
        toAdd = stod(decToAdd);
        amount += toAdd;
        strAmount = to_string(amount);
        encAmount = aesEncrypt(strAmount, aesKey, iv);
        auto endTime = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(endTime - beginTime).count();
        aesAvg += ms;
    }
    aesAvg /= iterations;
    cout << "Average time for AES-256: " << aesAvg << " microseconds" << endl;
    return aesAvg;
}

// Performs the addition benchmarking test for CKKS without relinearisation
int ckksAesAddBenchmarking(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        wstring encToAdd = aesEncrypt(to_string(toAdd), aesKey, iv);
        seal::Plaintext plain;
        seal::Ciphertext cipher;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher);
        auto start = chrono::high_resolution_clock::now();
        string strToAdd = aesDecrypt(encToAdd, aesKey, iv);
        toAdd = stod(strToAdd);
        seal::Ciphertext cipher2;
        encoder.encode(toAdd, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher2);
        eval.add_inplace(cipher, cipher2);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for the CKKS/AES-256 hybrid on the same settings as the banking systems: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}


// Performs the addition bencharking test for CKKS with relinearisation
int ckksAesAddBenchmarkingRelin(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        wstring encToAdd = aesEncrypt(to_string(toAdd), aesKey, iv);
        seal::Plaintext plain;
        seal::Ciphertext cipher;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher);
        auto start = chrono::high_resolution_clock::now();
        string strToAdd = aesDecrypt(encToAdd, aesKey, iv);
        toAdd = stod(strToAdd);
        seal::Ciphertext cipher2;
        encoder.encode(toAdd, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher2);
        eval.add_inplace(cipher, cipher2);
        eval.relinearize_inplace(cipher, relinKeys);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for CKKS while relinearising: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// Performs the subtraction benchmarking test for RSA
int rsaSubBenchmarking(int iterations, int keySize) {
    int rsaAvg = 0;
    string pubKey;
    string priKey;
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateRSAKey(pubKey, priKey, keySize);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        string strAmount = to_string(amount);
        string strToAdd = to_string(toAdd);
        string encAmount = RsaPubEncrypt(strAmount, pubKey);
        string encToAdd = RsaPubEncrypt(strToAdd, pubKey);
        auto beginTime = chrono::high_resolution_clock::now();
        string decAmount = RsaPriDecrypt(encAmount, priKey);
        string decToAdd = RsaPriDecrypt(encToAdd, priKey);
        amount = stod(decAmount);
        toAdd = stod(decToAdd);
        amount -= toAdd;
        strAmount = to_string(amount);
        encAmount = RsaPubEncrypt(strAmount, pubKey);
        auto endTime = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(endTime - beginTime).count();
        rsaAvg += ms;
    }
    rsaAvg /= iterations;
    cout << "Average time for RSA on " << keySize << " bits: " << rsaAvg << " microseconds" << endl;
    return rsaAvg;
}

// Performs the subtraction benchmarking test for AES
int aesSubBenchmarking(int iterations) {
    int keySize = 256;
    int aesAvg = 0;
    unsigned char* aesKey = new unsigned char[keySize];
    unsigned char* iv = new unsigned char[keySize / 2];
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        string strAmount = to_string(amount);
        string strToAdd = to_string(toAdd);
        wstring encAmount = aesEncrypt(strAmount, aesKey, iv);
        wstring encToAdd = aesEncrypt(strToAdd, aesKey, iv);
        auto beginTime = chrono::high_resolution_clock::now();
        string decAmount = aesDecrypt(encAmount, aesKey, iv);
        string decToAdd = aesDecrypt(encToAdd, aesKey, iv);
        amount = stod(decAmount);
        toAdd = stod(decToAdd);
        amount -= toAdd;
        strAmount = to_string(amount);
        encAmount = aesEncrypt(strAmount, aesKey, iv);
        auto endTime = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(endTime - beginTime).count();
        aesAvg += ms;
    }
    aesAvg /= iterations;
    cout << "Average time for AES-256: " << aesAvg << " microseconds" << endl;
    return aesAvg;
}

// Performs the subtraction benchmarking test for CKKS without relinearisation
int ckksAesSubBenchmarking(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        wstring encToAdd = aesEncrypt(to_string(toAdd), aesKey, iv);
        seal::Plaintext plain;
        seal::Ciphertext cipher;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher);
        auto start = chrono::high_resolution_clock::now();
        string strToAdd = aesDecrypt(encToAdd, aesKey, iv);
        toAdd = stod(strToAdd);
        seal::Ciphertext cipher2;
        encoder.encode(toAdd, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher2);
        eval.sub_inplace(cipher, cipher2);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for the CKKS/AES-256 hybrid on the same settings as the banking systems: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// Performs the subtraction benchmarking test for CKKS with relinearisation
int ckksAesSubBenchmarkingRelin(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        wstring encToAdd = aesEncrypt(to_string(toAdd), aesKey, iv);
        seal::Plaintext plain;
        seal::Ciphertext cipher;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher);
        auto start = chrono::high_resolution_clock::now();
        string strToAdd = aesDecrypt(encToAdd, aesKey, iv);
        toAdd = stod(strToAdd);
        seal::Ciphertext cipher2;
        encoder.encode(toAdd, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher2);
        eval.sub_inplace(cipher, cipher2);
        eval.relinearize_inplace(cipher, relinKeys);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for CKKS while relinearising: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// Performs the multiplication benchmarking test for RSA
int rsaMultBenchmarking(int iterations, int keySize) {
    int rsaAvg = 0;
    string pubKey;
    string priKey;
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateRSAKey(pubKey, priKey, keySize);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        string strAmount = to_string(amount);
        string strToAdd = to_string(toAdd);
        string encAmount = RsaPubEncrypt(strAmount, pubKey);
        string encToAdd = RsaPubEncrypt(strToAdd, pubKey);
        auto beginTime = chrono::high_resolution_clock::now();
        string decAmount = RsaPriDecrypt(encAmount, priKey);
        string decToAdd = RsaPriDecrypt(encToAdd, priKey);
        amount = stod(decAmount);
        toAdd = stod(decToAdd);
        amount *= toAdd;
        strAmount = to_string(amount);
        encAmount = RsaPubEncrypt(strAmount, pubKey);
        auto endTime = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(endTime - beginTime).count();
        rsaAvg += ms;
    }
    rsaAvg /= iterations;
    cout << "Average time for RSA on " << keySize << " bits: " << rsaAvg << " microseconds" << endl;
    return rsaAvg;
}

// Performs the multiplication benchmarking test for AES
int aesMultBenchmarking(int iterations) {
    int keySize = 256;
    int aesAvg = 0;
    unsigned char* aesKey = new unsigned char[keySize];
    unsigned char* iv = new unsigned char[keySize / 2];
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        string strAmount = to_string(amount);
        string strToAdd = to_string(toAdd);
        wstring encAmount = aesEncrypt(strAmount, aesKey, iv);
        wstring encToAdd = aesEncrypt(strToAdd, aesKey, iv);
        auto beginTime = chrono::high_resolution_clock::now();
        string decAmount = aesDecrypt(encAmount, aesKey, iv);
        string decToAdd = aesDecrypt(encToAdd, aesKey, iv);
        amount = stod(decAmount);
        toAdd = stod(decToAdd);
        amount *= toAdd;
        strAmount = to_string(amount);
        encAmount = aesEncrypt(strAmount, aesKey, iv);
        auto endTime = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(endTime - beginTime).count();
        aesAvg += ms;
    }
    aesAvg /= iterations;
    cout << "Average time for AES-256: " << aesAvg << " microseconds" << endl;
    return aesAvg;
}

// Performs the multiplication benchmarking test for CKKS without relinearisation
int ckksAesMultBenchmarkingNoRelin(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        wstring encToAdd = aesEncrypt(to_string(toAdd), aesKey, iv);
        seal::Plaintext plain;
        seal::Ciphertext cipher;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher);
        auto start = chrono::high_resolution_clock::now();
        string strToAdd = aesDecrypt(encToAdd, aesKey, iv);
        vector<double> res;
        decryptor.decrypt(cipher, plain);
        encoder.decode(plain, res);
        amount = res[0];
        amount *= (toAdd - 1);
        encoder.encode(amount, scale, plain);
        seal::Ciphertext cipher2;
        encryptor.encrypt_symmetric(plain, cipher2);
        eval.add_inplace(cipher, cipher2);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for the CKKS/AES-256 hybrid on the same settings as the banking systems: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// Performs the multiplication benchmarking test for CKKS with relinearisation
int ckksAesMultBenchmarkingRelin(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    seal::RelinKeys relinKeys;
    key = keyGen.secret_key();
    keyGen.create_relin_keys(relinKeys);
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        double toAdd = unif(re);
        seal::Plaintext plain;
        seal::Ciphertext cipher1;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher1);
        encoder.encode(toAdd, scale, plain);
        auto start = chrono::high_resolution_clock::now();
        seal::Ciphertext cipher2;
        encryptor.encrypt_symmetric(plain, cipher2);
        eval.multiply_inplace(cipher1, cipher2);
        eval.relinearize_inplace(cipher1, relinKeys);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for CKKS while relinearising: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// Performs the balance retrieval benchmarking test for AES
int aesDecryptBenchmark(int iterations) {
    int keySize = 256;
    int aesAvg = 0;
    unsigned char* aesKey = new unsigned char[keySize];
    unsigned char* iv = new unsigned char[keySize / 2];
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateAESKey(aesKey, iv);
    for (int i = 0; i < iterations; ++i) {
        double toDec = unif(re);
        wstring cipher = aesEncrypt(to_string(toDec), aesKey, iv);
        auto start = chrono::high_resolution_clock::now();
        string plain = aesDecrypt(cipher, aesKey, iv);
        toDec = stod(plain);
        auto finish = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(finish - start).count();
        aesAvg += ms;
    }
    aesAvg /= iterations;
    cout << "Average time for AES-256:" << aesAvg << " microseconds" << endl;
    return aesAvg;
}

// Performs the balance retrieval benchmarking test for RSA
int rsaDecryptBenchmark(int iterations, int keySize) {
    int aesAvg = 0;
    string pubKey, priKey;
    double lowerBound = 0.00;
    double upperBound = 10000.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    GenerateRSAKey(pubKey, priKey, keySize);
    for (int i = 0; i < iterations; ++i) {
        double toDec = unif(re);
        string cipher = RsaPubEncrypt(to_string(toDec), pubKey);
        auto start = chrono::high_resolution_clock::now();
        string plain = RsaPriDecrypt(cipher, priKey);
        toDec = stod(plain);
        auto finish = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(finish - start).count();
        aesAvg += ms;
    }
    aesAvg /= iterations;
    cout << "Average time for RSA on " << keySize << " bits:" << aesAvg << " microseconds" << endl;
}

// Performs the balance retrieval benchmarking test for CKKS without relinearisation
int ckksDecryptBenchmark(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    seal::RelinKeys relinKeys;
    key = keyGen.secret_key();
    keyGen.create_relin_keys(relinKeys);
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 1.00;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    GenerateAESKey(aesKey, iv);
    default_random_engine re;
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        seal::Plaintext plain;
        seal::Ciphertext cipher1;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher1);
        auto start = chrono::high_resolution_clock::now();
        vector<double> res;
        decryptor.decrypt(cipher1, plain);
        encoder.decode(plain, res);
        double result = res[0];
        wstring toSend = aesEncrypt(to_string(result), aesKey, iv);
        string received = aesDecrypt(toSend, aesKey, iv);
        result = stod(received);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for CKKS/AES-256 hybrid on the same settings as the banking system: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// Performs the balance retrieval benchmarking test for CKKS with relinearisation
int ckksDecryptBenchmarkRelin(int iterations) {
    int ckksAvg = 0;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key;
    seal::RelinKeys relinKeys;
    key = keyGen.secret_key();
    keyGen.create_relin_keys(relinKeys);
    seal::Encryptor encryptor(context, key);
    seal::Decryptor decryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator eval(context);
    double scale = pow(2, 20);
    double lowerBound = 0.00;
    double upperBound = 1.00;
    unsigned char* aesKey = new unsigned char[256];
    unsigned char* iv = new unsigned char[128];
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    GenerateAESKey(aesKey, iv);
    default_random_engine re;
    for (int i = 0; i < iterations; ++i) {
        double amount = unif(re);
        seal::Plaintext plain;
        seal::Ciphertext cipher1;
        encoder.encode(amount, scale, plain);
        encryptor.encrypt_symmetric(plain, cipher1);
        auto start = chrono::high_resolution_clock::now();
        vector<double> res;
        eval.relinearize_inplace(cipher1, relinKeys);
        decryptor.decrypt(cipher1, plain);
        encoder.decode(plain, res);
        double result = res[0];
        wstring toSend = aesEncrypt(to_string(result), aesKey, iv);
        string received = aesDecrypt(toSend, aesKey, iv);
        result = stod(received);
        auto end = chrono::high_resolution_clock::now();
        auto ms = chrono::duration_cast<chrono::microseconds>(end - start).count();
        ckksAvg += ms;
    }
    ckksAvg /= iterations;
    cout << "Average time for CKKS/AES-256 hybrid with relinearisation: " << ckksAvg << " microseconds" << endl;
    return ckksAvg;
}

// A test to see the average time taken to complete the set number of iterations without relinearisation
int relinTest(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    double track = 0.00;
    double start = 0.00;
    double toAdd;
    double scale = pow(2, 20);
    int avgTime = 0;
    encoder.encode(start, scale, plain1);
    encryptor.encrypt_symmetric(plain1, cipher1);
    for (int i = 0; i < iterations; ++i) {
        toAdd = round(100 * unif(re)) / 100;
        track += toAdd;
        encoder.encode(toAdd, scale, plain2);
        encryptor.encrypt_symmetric(plain2, cipher2);
        auto start = chrono::high_resolution_clock::now();
        eval.add_inplace(cipher1, cipher2);
        auto fin = chrono::high_resolution_clock::now();
        auto taken = chrono::duration_cast<chrono::microseconds>(fin - start).count();
        avgTime += taken;
        
    }
    cout << "Average time for " << iterations << " iterations: " << avgTime / iterations << " microseconds" << endl;
    return (avgTime / iterations);
}

// A test to see the average time taken to complete the set number of iterations with relinearisation
int relinTest2(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    double track = 0.00;
    double start = 0.00;
    double toAdd = 0.01;
    double scale = pow(2, 20);
    int avgTime = 0;
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    encoder.encode(start, scale, plain1);
    encryptor.encrypt_symmetric(plain1, cipher1);
    for (int i = 0; i < iterations; ++i) {
        toAdd = unif(re);
        track += toAdd;
        encoder.encode(toAdd, scale, plain2);
        encryptor.encrypt_symmetric(plain2, cipher2);
        auto start = chrono::high_resolution_clock::now();
        eval.add_inplace(cipher1, cipher2);
        eval.relinearize_inplace(cipher1, relinKeys);
        auto fin = chrono::high_resolution_clock::now();
        auto taken = chrono::duration_cast<chrono::microseconds>(fin - start).count();
        avgTime += taken;
    }
    cout << "Average time for " << iterations << " iterations: " << avgTime / iterations << " microseconds" << endl;
    return (avgTime / iterations);
}

// A test to see the average number time to failure with consecutive addition operations without relinearisation
int relinTest3(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    int runs = 0;
    for (int i = 0; i < iterations; ++i) {
        int counter = 0;
        double track = 0.00;
        double start = 0.00;
        double toAdd;
        double scale = pow(2, 20);
        double prev = 0.00;
        vector<double> result;
        result.push_back(prev);
        encoder.encode(start, scale, plain1);
        encryptor.encrypt_symmetric(plain1, cipher1);
        while (true) {
            toAdd = round(100 * unif(re)) / 100;
            track += toAdd;
            prev = result[0];
            encoder.encode(toAdd, scale, plain2);
            encryptor.encrypt_symmetric(plain2, cipher2);
            eval.add_inplace(cipher1, cipher2);
            decryptor.decrypt(cipher1, plain1);
            encoder.decode(plain1, result);
            stringstream ss;
            ss.precision(2);
            ss.setf(ios::fixed);
            ss << result[0];
            string out = ss.str();
            ss.str(string());
            ss << track;
            string out2 = ss.str();
            if (out2.compare(out) != 0) {
                runs += counter;
                break;
            }
            ++counter;
        }
    }
    cout << "Without relin: " << (runs / iterations) << endl;
    return runs / iterations;
}

// A test to see the average number time to failure with consecutive addition operations with relinearisation
int relinTest4(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    int runs = 0;
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    for (int i = 0; i < iterations; ++i) {
        int counter = 0;
        double track = 0.00;
        double start = 0.00;
        double toAdd;
        double scale = pow(2, 20);
        double prev = 0.00;
        vector<double> result;
        result.push_back(prev);
        encoder.encode(start, scale, plain1);
        encryptor.encrypt_symmetric(plain1, cipher1);
        while (true) {
            toAdd = round(100 * unif(re)) / 100;
            track += toAdd;
            prev = result[0];
            encoder.encode(toAdd, scale, plain2);
            encryptor.encrypt_symmetric(plain2, cipher2);
            eval.add_inplace(cipher1, cipher2);
            eval.relinearize_inplace(cipher1, relinKeys);
            decryptor.decrypt(cipher1, plain1);
            encoder.decode(plain1, result);
            stringstream ss;
            ss.precision(2);
            ss.setf(ios::fixed);
            ss << result[0];
            string out = ss.str();
            ss.str(string());
            ss << track;
            string out2 = ss.str();
            if (out2.compare(out) != 0) {
                runs += counter;
                break;
            }
            ++counter;
        }
    }
    cout << "With relin:" << (runs / iterations) << endl;
    return runs / iterations;
}

// A test to see the frequency distribution of times to failure with consecutive addition operations with relinearisation
vector<int> relinTest5(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    vector<int> runs;
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    for (int i = 0; i < iterations; ++i) {
        int counter = 0;
        double track = 0.00;
        double start = 0.00;
        double toAdd;
        double scale = pow(2, 20);
        double prev = 0.00;
        vector<double> result;
        result.push_back(prev);
        encoder.encode(start, scale, plain1);
        encryptor.encrypt_symmetric(plain1, cipher1);
        while (true) {
            toAdd = round(100 * unif(re)) / 100;
            track += toAdd;
            prev = result[0];
            encoder.encode(toAdd, scale, plain2);
            encryptor.encrypt_symmetric(plain2, cipher2);
            eval.add_inplace(cipher1, cipher2);
            eval.relinearize_inplace(cipher1, relinKeys);
            decryptor.decrypt(cipher1, plain1);
            encoder.decode(plain1, result);
            stringstream ss;
            ss.precision(2);
            ss.setf(ios::fixed);
            ss << result[0];
            string out = ss.str();
            ss.str(string());
            ss << track;
            string out2 = ss.str();
            if (out2.compare(out) != 0) {
                runs.push_back(counter);
                break;
            }
            ++counter;
        }
    }
    return runs;
}

// A test to see the frequency distribution of time to failure with consecutive addition operations without relinearisation
vector<int> relinTest6(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    double lowerBound = 0.00;
    double upperBound = 1.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    vector<int> runs;
    for (int i = 0; i < iterations; ++i) {
        int counter = 0;
        double track = 0.00;
        double start = 0.00;
        double toAdd;
        double scale = pow(2, 20);
        double prev = 0.00;
        vector<double> result;
        result.push_back(prev);
        encoder.encode(start, scale, plain1);
        encryptor.encrypt_symmetric(plain1, cipher1);
        while (true) {
            toAdd = round(100 * unif(re)) / 100;
            track += toAdd;
            prev = result[0];
            encoder.encode(toAdd, scale, plain2);
            encryptor.encrypt_symmetric(plain2, cipher2);
            eval.add_inplace(cipher1, cipher2);
            decryptor.decrypt(cipher1, plain1);
            encoder.decode(plain1, result);
            stringstream ss;
            ss.precision(2);
            ss.setf(ios::fixed);
            ss << result[0];
            string out = ss.str();
            ss.str(string());
            ss << track;
            string out2 = ss.str();
            if (out2.compare(out) != 0) {
                runs.push_back(counter);
                break;
            }
            ++counter;
        }
    }
    return runs;
}

// A test to see the frequency distribution of time to failure with consecutive multiplication operations without relinearisation
vector<int> relinTest7(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    double lowerBound = 1.00;
    double upperBound = 2.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    vector<int> runs;
    for (int i = 0; i < iterations; ++i) {
        int counter = 0;
        try {
        double track = 1.00;
        double start = 1.00;
        double toAdd;
        double scale = pow(2, 20);
        double prev = 1.00;
        vector<double> result;
        result.push_back(prev);
        encoder.encode(start, scale, plain1);
        encryptor.encrypt_symmetric(plain1, cipher1);
        while (true) {
            cout << counter << endl;
            toAdd = round(100 * unif(re)) / 100;
            track *= toAdd;
            prev = result[0];
            encoder.encode(toAdd, scale, plain2);
            encryptor.encrypt_symmetric(plain2, cipher2);
            eval.multiply_inplace(cipher1, cipher2);
            decryptor.decrypt(cipher1, plain1);
            encoder.decode(plain1, result);
            stringstream ss;
            ss.precision(2);
            ss.setf(ios::fixed);
            ss << result[0];
            string out = ss.str();
            ss.str(string());
            ss << track;
            string out2 = ss.str();
            cout << out2 << endl << out << endl << "_____________" << endl;
            if (out2.compare(out) != 0) {
                runs.push_back(counter);
                break;
            }
            ++counter;
        }
        }
        catch (exception& e) {
            cout << e.what() << endl;
            runs.push_back(counter);
        }
    }
    return runs;
}

// A test to see the frequency distribution of time to failure with consecutive mulitplication operations with relinearisation
vector<int> relinTest8(int iterations) {
    seal::Ciphertext cipher1, cipher2, cipher3;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params(seal::scheme_type::ckks);
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    double lowerBound = 1.00;
    double upperBound = 2.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    vector<int> runs;
    for (int i = 0; i < iterations; ++i) {
        int counter = 0;
        try {
            double track = 1.00;
            double start = 1.00;
            double toAdd;
            double scale = pow(2, 20);
            double prev = 1.00;
            vector<double> result;
            encoder.encode(start, scale, plain1);
            encryptor.encrypt_symmetric(plain1, cipher1);
            encryptor.encrypt_symmetric(plain1, cipher3);
            while (true) {
                cout << counter << endl;
                toAdd = round(100 * unif(re)) / 100;
                track *= toAdd;
                encoder.encode(toAdd, scale, plain2);
                seal::Ciphertext cipher2;
                encryptor.encrypt_symmetric(plain2, cipher2);
                cout << "Before multiplication: " << log2(cipher1.scale()) << endl;
                cout << "Cipher 2 scale: " << log2(cipher2.scale()) << endl;
                eval.multiply_plain_inplace(cipher1, plain2);
                eval.relinearize_inplace(cipher1, relinKeys);
                decryptor.decrypt(cipher1, plain1);
                encoder.decode(plain1, result);
                stringstream ss;
                ss.precision(2);
                ss.setf(ios::fixed);
                ss << result[0];
                string out = ss.str();
                ss.str(string());
                ss << track;
                string out2 = ss.str();
                cout << "Expected: " << out2 << endl << "Received: " << out << endl << "_____________" << endl;
                if (out2.compare(out) != 0) {
                    runs.push_back(counter);
                    break;
                }
                ++counter;
                start = result[0];
                encoder.encode(start, scale, plain1);
                encryptor.encrypt_symmetric(plain1, cipher1);
            }
        }
        catch (exception& e) {
            cout << e.what() << endl;
            runs.push_back(counter);
        }
    }
    return runs;
}

// A test to see the average number time to failure with consecutive multiplication operations without relinearisation
int relinTest9(int iterations) {
    try {
        seal::Ciphertext cipher1, cipher2;
        seal::Plaintext plain1, plain2;
        seal::EncryptionParameters params;
        loadCKKSParams(params);
        seal::SEALContext context(params);
        seal::KeyGenerator keyGen(context);
        seal::SecretKey key = keyGen.secret_key();
        seal::Encryptor encryptor(context, key);
        seal::CKKSEncoder encoder(context);
        seal::Decryptor decryptor(context, key);
        seal::Evaluator eval(context);
        double lowerBound = 1.00;
        double upperBound = 2.00;
        std::uniform_real_distribution<double> unif(lowerBound, upperBound);
        default_random_engine re;
        double start = 1.00;
        double toAdd;
        double scale = pow(2, 20);
        int avgTime = 0;
        encoder.encode(start, scale, plain1);
        encryptor.encrypt_symmetric(plain1, cipher1);
        for (int i = 0; i < iterations; ++i) {
            toAdd = round(100 * unif(re)) / 100;
            encoder.encode(toAdd, scale, plain2);
            encryptor.encrypt_symmetric(plain2, cipher2);
            auto start = chrono::high_resolution_clock::now();
            eval.multiply_inplace(cipher1, cipher2);
            auto fin = chrono::high_resolution_clock::now();
            auto taken = chrono::duration_cast<chrono::microseconds>(fin - start).count();
            avgTime += taken;
            encryptor.encrypt_symmetric(plain1, cipher1);
        }
        cout << "Average time for " << iterations << " iterations: " << avgTime / iterations << " microseconds" << endl;
        return (avgTime / iterations);
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
}

// A test to see the average number time to failure with consecutive addition operations with relinearisation
int relinTest10(int iterations) {
    seal::Ciphertext cipher1, cipher2;
    seal::Plaintext plain1, plain2;
    seal::EncryptionParameters params;
    loadCKKSParams(params);
    seal::SEALContext context(params);
    seal::KeyGenerator keyGen(context);
    seal::SecretKey key = keyGen.secret_key();
    seal::Encryptor encryptor(context, key);
    seal::CKKSEncoder encoder(context);
    seal::Decryptor decryptor(context, key);
    seal::Evaluator eval(context);
    seal::RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);
    double lowerBound = 1.00;
    double upperBound = 2.00;
    std::uniform_real_distribution<double> unif(lowerBound, upperBound);
    default_random_engine re;
    double start = 1.00;
    double toAdd;
    double scale = pow(2, 20);
    int avgTime = 0;
    encoder.encode(start, scale, plain1);
    encryptor.encrypt_symmetric(plain1, cipher1);
    for (int i = 0; i < iterations; ++i) {
        toAdd = round(100 * unif(re)) / 100;
        encoder.encode(toAdd, scale, plain2);
        encryptor.encrypt_symmetric(plain2, cipher2);
        auto start = chrono::high_resolution_clock::now();
        eval.multiply_inplace(cipher1, cipher2);
        eval.relinearize_inplace(cipher1, relinKeys);
        auto fin = chrono::high_resolution_clock::now();
        auto taken = chrono::duration_cast<chrono::microseconds>(fin - start).count();
        avgTime += taken;
        encryptor.encrypt_symmetric(plain1, cipher1);
    }
    cout << "Average time for " << iterations << " iterations: " << avgTime / iterations << " microseconds" << endl;
    return (avgTime / iterations);
}



int main()
{
    try {
        vector<int> iterations = { 10, 100, 1000, 10000 };

        cout << "Without relinearisation" << endl;
        for (int i : iterations) {
            relinTest(i);
            relinTest9(i);
        }

        cout << "With relinearisation: " << endl;
        for (int i : iterations) {
            relinTest2(i);
            relinTest10(i);
        }
        
        thread relin1(relinTest3, 1000);
        thread relin2(relinTest4, 1000);

        relin1.join();
        relin2.join();

        vector<int> runs = relinTest6(1000);
        ofstream out5("relinTest6.txt");

        for (int i = 0; i < runs.size(); ++i) {
            out5 << runs[i] << endl;
        }
        
        out5.close();
        ofstream out6("relinTest5.txt");
        runs = relinTest5(1000);
        for (int i = 0; i < runs.size(); ++i) {
            out6 << runs[i] << endl;
        }
        cout << 5 << endl;
        out6.close();

        ofstream out7("relinTest7.txt");
        runs = relinTest7(1000);
        for (int i = 0; i < runs.size(); ++i) {
            out7 << runs[i] << endl;
        }
        cout << 7 << endl;
        out7.close();

        ofstream out8("relinTest8.txt");
        runs = relinTest8(1000);
        for (int i = 0; i < runs.size(); ++i) {
            out8 << runs[i] << endl;
        }
        cout << 8 << endl;
        out8.close();


        int it = 10000;
        cout << "Addition:" << endl;
        thread aesAddThread(aesAddBenchmarking, it);
        thread rsaAddThread1(rsaAddBenchmarking, it, 2048);
        thread ckksAddThread(ckksAesAddBenchmarking, it);
        thread rsaAddThread2(rsaAddBenchmarking, it, 4096);
        thread ckksAddThread2(ckksAesAddBenchmarkingRelin, it);
        aesAddThread.join();
        rsaAddThread1.join();
        ckksAddThread.join();
        rsaAddThread2.join();
        ckksAddThread2.join();

        cout << "Subtraction:" << endl;
        thread aesSubThread(aesSubBenchmarking, it);
        thread rsaSubThread1(rsaSubBenchmarking, it, 2048);
        thread ckksSubThread(ckksAesSubBenchmarking, it);
        thread rsaSubThread2(rsaSubBenchmarking, it, 4096);
        thread ckksSubThread2(ckksAesSubBenchmarkingRelin, it);

        aesSubThread.join();
        rsaSubThread1.join();
        ckksSubThread.join();
        rsaSubThread2.join();
        ckksSubThread2.join();

        cout << "Multiplication:" << endl;
        thread aesMultThread(aesMultBenchmarking, it);
        thread rsaMultThread1(rsaMultBenchmarking, it, 2048);
        thread ckksMultThread1(ckksAesMultBenchmarkingRelin, it);
        thread ckksMultThread2(ckksAesMultBenchmarkingNoRelin, it);
        thread rsaMultThread2(rsaMultBenchmarking, it, 4096);

        aesMultThread.join();
        rsaMultThread1.join();
        ckksMultThread1.join();
        ckksMultThread2.join();
        rsaMultThread2.join();

        cout << "Decryption:" << endl;
        thread aesDecryptThread(aesDecryptBenchmark, it);
        thread rsaDecryptThread1(rsaDecryptBenchmark, it, 2048);
        thread ckksDecryptThread(ckksDecryptBenchmark, it);
        thread rsaDecryptThread2(rsaDecryptBenchmark, it, 4096);

        aesDecryptThread.join();
        rsaDecryptThread1.join();
        ckksDecryptThread.join();
        rsaDecryptThread2.join();
        
    }
    catch (exception& e) {
        cout << e.what() << endl;
    }
}