#include <iostream>
#include <fstream>
#include <gmp.h>
#include <bitcoin/bitcoin.hpp>

int main() {
    // Initialize GMP variables
    mpz_t start, end, current;
    mpz_init_set_str(start, "0000000000000000000000000000000000000000000000020000000000000000", 16);
    mpz_init_set_str(end, "000000000000000000000000000000000000000000000003ffffffffffffffff", 16);
    mpz_init_set(current, start);

    // Open the output file
    std::ofstream file("bitcoin_keys_and_addresses.txt");
    if (!file) {
        std::cerr << "Failed to open file for writing.\n";
        return 1;
    }

    // Bitcoin library setup
    bc::wallet::payment_address address;
    bc::secret secret;
    bc::ec_secret ec_secret;

    // Loop through the range
    while (mpz_cmp(current, end) <= 0) {
        // Convert current number to hex private key
        char* private_key_hex = mpz_get_str(nullptr, 16, current);
        
        // Convert hex to Bitcoin secret
        bc::decode_base16(secret.data(), private_key_hex);
        ec_secret = bc::secret_to_public_key(secret);
        address = bc::wallet::payment_address(bc::wallet::ec_private(secret).to_public().to_payment_address());

        // Write private key and address to file
        file << private_key_hex << " " << address.encoded() << "\n";

        // Free allocated memory
        free(private_key_hex);

        // Increment current key
        mpz_add_ui(current, current, 1);
    }

    // Cleanup GMP variables
    mpz_clear(start);
    mpz_clear(end);
    mpz_clear(current);

    file.close();
    std::cout << "Keys and addresses have been written to bitcoin_keys_and_addresses.txt\n";

    return 0;
}
