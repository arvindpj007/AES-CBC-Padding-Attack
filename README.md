# AES-CBC-Padding-Attack
> Golang programs for Padding Oracle attack for AES CBC mode.

1. `encrypt-auth` contains `main.go` program to perform AES encryption in CBC mode with HMAC. Here the AES and SHA256 functions are used from the standard package, but the CBC mode encryption and HMAC calculations are performed in program.
    
    To build the binary, the following command can be performed:
            
        go build
    The encryption/decryption can be performed with the following command:

        ./encrypt <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>
    mode = `encrypt` or `decrypt` and first 16 bytes of the key is used for encryption and last 16 bytes of MAC calculation.

2. `decrypt-test` contains `main.go` program that works like the oracle. The program `./decrypt-test` that has the key K hardcoded into it. It performs decryption of the provided cipher text and it will not return the decrypted ciphertext, but instead only a single one of the following three response messages:
    1. “SUCCESS”
    2. “INVALID PADDING” 
    3. “INVALID MAC”

    The command-line profile for decrypt-test will be as follows:

        ./decrypt-test -i <ciphertext file>

3. `decrypt-attack` contains `main.go` program that performs the padding oracle attack. The program takes a cipher text as the input programmatically decrypts and returns the plain text of any ciphertext produced by your encryption utility from `encrypt-auth` with the help of `./decrypt-test`. It will not have access to a decrypt-key. The command-line profile for decrypt-test will be as follows:

        ./decrypt-attack -i <ciphertext file>
