package main

import (
	"crypto/aes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

//A binary to hexadecimal map
var binHexMap = make(map[string]string)
var hexBinMap = make(map[string]string)
var paddingMap = make(map[int]string)
var reversePaddingMap = make(map[string]int)

//Function to setup and initialize the binary to hexadecimal mapping
func setupBinHexMap() {

	binHexMap["0000"] = "0"
	binHexMap["0001"] = "1"
	binHexMap["0010"] = "2"
	binHexMap["0011"] = "3"
	binHexMap["0100"] = "4"
	binHexMap["0101"] = "5"
	binHexMap["0110"] = "6"
	binHexMap["0111"] = "7"
	binHexMap["1000"] = "8"
	binHexMap["1001"] = "9"
	binHexMap["1010"] = "a"
	binHexMap["1011"] = "b"
	binHexMap["1100"] = "c"
	binHexMap["1101"] = "d"
	binHexMap["1110"] = "e"
	binHexMap["1111"] = "f"
}

//Function to setup and initialize the hexadecimal to binary mapping
func setupHexBinMap() {

	hexBinMap["0"] = "0000"
	hexBinMap["2"] = "0010"
	hexBinMap["1"] = "0001"
	hexBinMap["3"] = "0011"
	hexBinMap["4"] = "0100"
	hexBinMap["5"] = "0101"
	hexBinMap["6"] = "0110"
	hexBinMap["7"] = "0111"
	hexBinMap["8"] = "1000"
	hexBinMap["9"] = "1001"
	hexBinMap["a"] = "1010"
	hexBinMap["b"] = "1011"
	hexBinMap["c"] = "1100"
	hexBinMap["d"] = "1101"
	hexBinMap["e"] = "1110"
	hexBinMap["f"] = "1111"
}

//Function to setup and initialize the length to padding mapping
func setupPadding() {

	paddingMap[0] = "10101010101010101010101010101010"
	paddingMap[1] = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	paddingMap[2] = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
	paddingMap[3] = "0d0d0d0d0d0d0d0d0d0d0d0d0d"
	paddingMap[4] = "0c0c0c0c0c0c0c0c0c0c0c0c"
	paddingMap[5] = "0b0b0b0b0b0b0b0b0b0b0b"
	paddingMap[6] = "0a0a0a0a0a0a0a0a0a0a"
	paddingMap[7] = "090909090909090909"
	paddingMap[8] = "0808080808080808"
	paddingMap[9] = "07070707070707"
	paddingMap[10] = "060606060606"
	paddingMap[11] = "0505050505"
	paddingMap[12] = "04040404"
	paddingMap[13] = "030303"
	paddingMap[14] = "0202"
	paddingMap[15] = "01"
}

//Function to setup and initialize the length to padding mapping
func setupReversePadding() {

	reversePaddingMap["10"] = 0
	reversePaddingMap["0f"] = 1
	reversePaddingMap["0e"] = 2
	reversePaddingMap["0d"] = 3
	reversePaddingMap["0c"] = 4
	reversePaddingMap["0b"] = 5
	reversePaddingMap["0a"] = 6
	reversePaddingMap["09"] = 7
	reversePaddingMap["08"] = 8
	reversePaddingMap["07"] = 9
	reversePaddingMap["06"] = 10
	reversePaddingMap["05"] = 11
	reversePaddingMap["04"] = 12
	reversePaddingMap["03"] = 13
	reversePaddingMap["02"] = 14
	reversePaddingMap["01"] = 15
}

//Funciton to throw an error when the input CLI has missing/wrong parameters
func missingParametersError() {

	fmt.Println("ERROR: Parameters missing!")
	fmt.Println("HELP:")
	fmt.Println("encrypt-auth <mode> -k <32-byte key in hexadecimal> -i <input file> -o <outputfile>")
	fmt.Println("set <mode> as 'encrypt' or 'decrypt'")

}

//Funciton to setup the CLI
func setupCLI() string {

	var input string

	InputPtr := flag.String("i", "", "location of raw binary data cipher text file")

	if len(os.Args) < 2 {

		missingParametersError()
		flag.PrintDefaults()
		os.Exit(1)

	}

	flag.Parse()

	input = *InputPtr

	if input == "" {
		missingParametersError()
		flag.PrintDefaults()
		os.Exit(1)
	}

	return input

}

//Function that converts a string of binary to a string of hexadecimal => coverts every 4 bits of binary to hexadecimal
func binToHex(binaryText string) string {

	var hexText string

	for i := 0; i < len(binaryText); i += 4 {

		binaryTextPart := binaryText[0+i : 4+i]
		hexText += binHexMap[binaryTextPart]
	}
	return hexText
}

//Function that converts a string of hexadecimal to a string of binary => coverts every 1 hexadecimal value to binary
func hexToBin(hexText string) string {

	var binaryText string

	for i := 0; i < len(hexText); i++ {

		hexTextPart := hexText[0+i : 1+i]

		binaryText += hexBinMap[hexTextPart]
		// fmt.Println("hex text part: ", hexTextPart, hexBinMap[hexTextPart])
	}
	return binaryText
}

//Function to get the binary value from the given input file and return hexadecimal value
func getInputText(inputText string) string {

	file, err := os.Open(inputText)
	if err != nil {
		log.Fatal(err)
	}

	dataBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	binaryText := string(dataBytes)

	size := len(binaryText)
	if size%8 != 0 {

		fmt.Println("ERROR: Please provide the input text with octet strings of raw binary data")
		os.Exit(1)
	}

	// fmt.Println(binaryText)
	return binToHex(binaryText)
}

//Function to perform XOR of two n/2 bytes hexadecimals and returns result in hexadecimal
func hexXOR(input1 string, input2 string, n int) string {

	var s string

	// fmt.Println(input1, len(input1))
	// fmt.Println(input2, len(input2))

	for i := 0; i < n; i += 16 {

		x, _ := strconv.ParseUint(input1[0+i:16+i], 16, 64)
		y, _ := strconv.ParseUint(input2[0+i:16+i], 16, 64)
		z := x ^ y
		h := fmt.Sprintf("%x", z)
		n := len(h)
		for i := 16 - n; i != 0; i-- {
			h = "0" + h
		}
		// fmt.Println("Hex: ", h)
		s += fmt.Sprintf("%s", h)

	}

	return s

}

//Funciton to get integer byte array from hexadecimal values
func hexToBytes(hexadecimal string) []byte {

	n := len(hexadecimal)
	var intBytes = make([]byte, int(n/2))

	for i := 0; i < len(intBytes); i++ {
		x, _ := strconv.ParseUint(hexadecimal[0+i*2:2+i*2], 16, 64)
		intBytes[i] = byte(x)
	}

	return intBytes
}

//Funciton to perform HMAC-SHA256 return the same
func hmacSHA256(macKeyExtracted string, plaintext string) string {

	var macKeyHex string
	var macKeyPad string
	var ipadHex string
	var opadHex string

	ipadHex = "3636363636363636363636363636363636363636363636363636363636363636"
	opadHex = "5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C"

	// macKeyExtracted = "6368616e676520746869732070617373776f726420746f206120736563726574" // should come from the parameters
	macKeyPad = "00000000000000000000000000000000"
	macKeyHex = macKeyExtracted + macKeyPad

	// fmt.Println("macKeyExtracted: ", macKeyExtracted, len(macKeyExtracted))
	// fmt.Println("macKeyHexAfterappend: ", macKeyHex, len(macKeyHex)) //, hexXOR(macKeyHex, ipadHex))

	innerValue := hexXOR(macKeyHex, ipadHex, 64) + plaintext

	// fmt.Println(hexXOR(macKeyHex, ipadHex))
	// fmt.Println("inner: ", hexToBytes(innerValue))
	h := sha256.New()
	innerValueBytes := hexToBytes(innerValue)
	h.Write(innerValueBytes)
	innerValueHex := fmt.Sprintf("%x", h.Sum(nil))
	// fmt.Println("inner hash1", h.Sum(nil))
	// fmt.Println("inner hash2", hexToBytes(innerValueHex))
	outerValue := hexXOR(macKeyHex, opadHex, 64) + innerValueHex
	h = sha256.New()
	outerValueBytes := hexToBytes(outerValue)
	h.Write(outerValueBytes)
	outerValueHex := fmt.Sprintf("%x", h.Sum(nil))

	// fmt.Println(hexXOR(macKeyHex, opadHex))
	// fmt.Println(outerValue)

	return outerValueHex //return this value

}

//Funciton that performs the AES-CBC decryption
func aescbcDecrypt(aesKey, hmacKey, cipher string) string {

	var byteDecrypted []byte
	var hexDecrypted string
	var plaintext string
	var plaintextAndHmac string
	var plaintextAndHmacAndPadding string
	var assumedPadding string
	var assumedHMAC string
	var paddingCheck bool
	var hmacCheck bool
	c := make(map[int]string)

	// fmt.Println(cipher, len(cipher))

	keyDecryption := hexToBytes(aesKey)                // this key will be used for the whole AES-CBC mode encryption
	aesDecryption, err := aes.NewCipher(keyDecryption) // this the AES-ECB mode that enciphers using the key
	if err != nil {
		fmt.Println(err)
	}

	// fmt.Println(cipher[0:32])
	// fmt.Println(cipher[32:64])
	// fmt.Println(cipher[64:96])
	// fmt.Println(cipher[96:128])

	// c[0] = hexToBin(iv)
	// ciphertext = c[0]
	c[0] = cipher[0:32]
	// fmt.Println("iv: ", c[0])
	for i := 1; i < int(len(cipher)/32); i++ {

		c[i] = cipher[i*32 : 32+i*32]
		// fmt.Println(c[i], len(c[i]))
		byteDecrypted = make([]byte, 16)
		aesDecryption.Decrypt(byteDecrypted, hexToBytes(c[i]))
		hexDecrypted = fmt.Sprintf("%x", byteDecrypted)
		// fmt.Println("After decryption: ", hexDecrypted)
		// fmt.Println("After xor: ", hexXOR(c[i-1], hexDecrypted, 32))
		plaintextAndHmacAndPadding += hexXOR(c[i-1], hexDecrypted, 32)
	}

	// fmt.Println(plaintextAndHmacAndPadding)

	// Padding Check
	lengthOfPlainText := len(plaintextAndHmacAndPadding)
	lastByte := plaintextAndHmacAndPadding[lengthOfPlainText-2 : lengthOfPlainText]

	n := reversePaddingMap[lastByte]
	m := 0
	m = (16 - n)
	// fmt.Println(n)
	if lengthOfPlainText-2*m < 0 {
		return "INVALID PADDING"
	}
	assumedPadding = plaintextAndHmacAndPadding[lengthOfPlainText-2*m : lengthOfPlainText]
	// fmt.Println("assumed: ", assumedPadding, "expected: ", paddingMap[n])
	if assumedPadding == paddingMap[n] {

		paddingCheck = true

	} else {
		paddingCheck = false
	}

	if paddingCheck == false {
		return "INVALID PADDING"

	}

	plaintextAndHmac = plaintextAndHmacAndPadding[0 : lengthOfPlainText-len(assumedPadding)]
	// fmt.Println(plaintextAndHmac, plaintext)
	// Plaintext and HMAC recovery
	if len(plaintextAndHmac)-64 < 0 {
		return "INVALID MAC"
	}
	plaintext = plaintextAndHmac[0 : len(plaintextAndHmac)-64]
	assumedHMAC = plaintextAndHmac[len(plaintextAndHmac)-64 : len(plaintextAndHmac)]
	expectedHMAC := hmacSHA256(hmacKey, plaintext)
	if assumedHMAC == expectedHMAC {
		hmacCheck = true
	} else {
		hmacCheck = false
	}
	if hmacCheck == false {
		return "INVALID MAC"
	}

	return "SUCCESS"
}

func main() {

	var input string

	input = setupCLI()
	hmacKey := "6368616e676520746869732070617373"
	aesKey := "776f726420746f206120736563726574"

	setupBinHexMap()
	setupHexBinMap()
	setupPadding()
	setupReversePadding()
	cipherText := getInputText(input) // from CLI
	// fmt.Println("Decrypt Test Starting... ", cipherText) //, len(cipherText))
	result := aescbcDecrypt(aesKey, hmacKey, cipherText) //from CLI split keys

	// fmt.Println("Decryption Test Complete")
	fmt.Println(result)

	// fmt.Println(hexXOR("d09a798087ed81202e5c96315d4eb852", "7343dfa2b8950ca0504b07ce73083dee", 32))
	// fmt.Println(mode, key, input, output)

}
