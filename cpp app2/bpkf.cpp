#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <omp.h>
#include <iomanip>
#include <sstream>

// Function to convert a byte array to a hex string
std::string toHexString(const std::vector<unsigned char>& v) {
    std::ostringstream oss;
    for (auto b : v)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

// Function to compute SHA-256 hash
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256);
    return hash;
}

// Function to compute RIPEMD-160 hash
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, data.data(), data.size());
    RIPEMD160_Final(hash.data(), &ripemd160);
    return hash;
}

// Function to compute the Bitcoin address from a public key
std::string publicKeyToBitcoinAddress(const std::vector<unsigned char>& publicKey) {
    std::vector<unsigned char> sha256Hash = sha256(publicKey);
    std::vector<unsigned char> ripemd160Hash = ripemd160(sha256Hash);

    std::vector<unsigned char> address;
    address.push_back(0x00); // Main network
    address.insert(address.end(), ripemd160Hash.begin(), ripemd160Hash.end());

    std::vector<unsigned char> checksum = sha256(sha256(address));
    address.insert(address.end(), checksum.begin(), checksum.begin() + 4);

    return toHexString(address);
}

// Function to generate a private key and derive its corresponding public key
std::vector<unsigned char> generatePublicKey(const std::vector<unsigned char>& privateKey) {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* privKeyBN = BN_bin2bn(privateKey.data(), privateKey.size(), NULL);
    EC_KEY_set_private_key(ecKey, privKeyBN);

    const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
    EC_POINT* pubKeyPoint = EC_POINT_new(ecGroup);
    EC_POINT_mul(ecGroup, pubKeyPoint, privKeyBN, NULL, NULL, NULL);
    EC_KEY_set_public_key(ecKey, pubKeyPoint);

    int pubKeyLen = i2o_ECPublicKey(ecKey, NULL);
    std::vector<unsigned char> publicKey(pubKeyLen);
    unsigned char* pubKeyData = publicKey.data();
    i2o_ECPublicKey(ecKey, &pubKeyData);

    EC_POINT_free(pubKeyPoint);
    BN_free(privKeyBN);
    EC_KEY_free(ecKey);

    return publicKey;
}

// Function to convert an integer to a byte array
std::vector<unsigned char> intToBytes(uint64_t value) {
    std::vector<unsigned char> bytes(32, 0);
    for (int i = 31; i >= 0; --i) {
        bytes[i] = value & 0xFF;
        value >>= 8;
    }
    return bytes;
}

int main() {
    uint64_t start = 0x2000000000000000;
    uint64_t end = 0x3ffffffffffffffff;
    std::string targetAddress = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so";
    std::ofstream outFile("private_keys.txt");

    #pragma omp parallel for
    for (uint64_t i = start; i <= end; ++i) {
        std::vector<unsigned char> privateKey = intToBytes(i);
        std::vector<unsigned char> publicKey = generatePublicKey(privateKey);
        std::string address = publicKeyToBitcoinAddress(publicKey);

        if (address == targetAddress) {
            #pragma omp critical
            {
                outFile << toHexString(privateKey) << std::endl;
            }
        }
    }

    outFile.close();
    return 0;
}
