#include <stdio.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>


std::string sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string read_file_key(std::string filename) {
    std::ifstream infile(filename);
    std::string s;
    infile >> s;
    return s;
}


int main(int argc, char **argv) {
    std::string SID = "UDI11-235-2";                // Get from the Windows API
    std::string aux_str = "deadman@fuck.com";       // Fixed in the source code
    std::string hash_key = sha256(SID+aux_str);     // Hash the two strings
    printf("Hashed string: %s\n", hash_key.c_str());       

    // Read file_key from the file
    std::string file_key = read_file_key("key.md5");

    // If two keys are identical
    if (hash_key == file_key) {
        printf("Go ahead\n");
    }
    else {
        printf("Key is incorrect, please register\n");
    }
}
