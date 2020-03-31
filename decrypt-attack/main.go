package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	fmt.Println("decrypt-attack -i <input file>")
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

//Function that converts a string of hexadecimal to a string of binary => coverts every 1 hexadecimal value to 4 bits of binary
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

//Funciton to set the check.txt file which is used by the oracle server for testing
func setCheckFile(text string) {

	file, err := os.OpenFile("check.txt", os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
		fmt.Println("ERROR: cannot open: ", err)
	}

	l, err := file.WriteString(text)
	// fmt.Println(text)
	if err != nil {
		fmt.Println("ERROR: cannot write", err)
		file.Close()
		return
	}
	// fmt.Println(l, "bits written successfully to the file")
	for i := 0; i < l; i++ {
		// fmt.Println(".")
	}
	file.Sync()
	file.Close()
}

//Function that returns the result after oracle processes the input from check.txt
func getDecryptTestResult() string {

	cmd := exec.Command("./decrypt-test", "-i", "check.txt")
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println("Error in calling test function:", err)
		log.Fatal(err)
	}

	result := strings.Split((string(stdout)), "\n")
	return result[len(result)-2]
}

func partitionCipherText(cipherText string) ([]string, int) {

	size := len(cipherText)

	if size%32 != 0 {
		fmt.Println("Error")
	}

	numberOfPartitions := int(size / 32)
	var partedCipherText = make([]string, numberOfPartitions)

	for i := 0; i < numberOfPartitions; i++ {

		partedCipherText[i] = cipherText[0+i*32 : 32+i*32]
	}

	return partedCipherText, numberOfPartitions
}

//Makes the block size (16 bytes) proper by appending n "f0" byte(s) in front of the string
func duplicateZeros(n int) string {
	var zero string
	for i := 0; i < n; i++ {
		zero += "f0"
	}

	return zero
}

func oracleAttack(iv string, cipherText string) string {

	var lastBlock string
	var plainText string

	for j := 0; j < 16; j++ {

		for i := 0; i < 256; i++ {
			// fmt.Println("IV: ", iv)

			nextByte := fmt.Sprintf("%x", i)

			if len(nextByte) == 1 {
				nextByte = "0" + nextByte
			}

			flippingByte := duplicateZeros(15-j) + nextByte + lastBlock

			// fmt.Println(j, i, flippingByte, nextByte, lastBlock)

			checkCipher := hexXOR(iv, flippingByte, 32) + cipherText
			setCheckFile(hexToBin(checkCipher))
			testResult := getDecryptTestResult()
			// fmt.Println(testResult)

			if testResult == "INVALID MAC" {

				// fmt.Println(flippingByte)
				padding := paddingMap[15-j]
				nPadding := ((32 - len(padding)) / 2)
				fullPadding := duplicateZeros(nPadding) + padding
				// fmt.Println("padding: ", fullPadding)

				partPlainText := hexXOR(flippingByte, fullPadding, 32)
				npartPlainText := len(partPlainText)
				plainText = partPlainText[npartPlainText-2*(j+1):npartPlainText-2*j] + plainText
				// fmt.Println("plainText: ", plainText)

				nextPadding := paddingMap[15-j-1]
				nNextPadding := ((32 - len(nextPadding)) / 2)
				fullNextPadding := duplicateZeros(nNextPadding) + nextPadding
				// fmt.Println("next padding: ", nextPadding)

				nPlainText := ((32 - len(plainText)) / 2)
				fullPlainText := duplicateZeros(nPlainText) + plainText

				lastBlock = hexXOR(fullNextPadding, fullPlainText, 32)
				// fmt.Println("XOR last block:", lastBlock)
				nLastBlock := len(lastBlock)
				lastBlock = lastBlock[nLastBlock-(j+1)*2 : nLastBlock]
				// fmt.Println("last block:", lastBlock)
				break
			}
		}

	}
	return (plainText)
}

func main() {

	var input string
	var cipherText string
	var plainText string
	var plaintextAndHmac string
	var plaintextAndHmacAndPadding string
	var partedCipherText []string
	var numberOfPartitions int

	setupBinHexMap()
	setupHexBinMap()
	setupPadding()
	setupReversePadding()

	// fmt.Println("Decrypt Attack starting...")

	input = setupCLI()
	cipherText = getInputText(input)

	partedCipherText, numberOfPartitions = partitionCipherText(cipherText)

	// setCheckFile(hexToBin())
	var partedPlainText = make([]string, numberOfPartitions)

	for i := numberOfPartitions - 1; i > 0; i-- {

		partedPlainText[i] = oracleAttack(partedCipherText[i-1], partedCipherText[i])
	}

	// x := oracleAttack(partedCipherText[17], partedCipherText[18])
	// fmt.Println("IV: ", partedCipherText[17], "Cipher Text: ", partedCipherText[18])
	// fmt.Println("Plain Text: ")
	for i := 0; i < numberOfPartitions; i++ {
		plaintextAndHmacAndPadding += partedPlainText[i]
	}

	nPlaintextAndHmacAndPadding := len(plaintextAndHmacAndPadding)
	lastByte := plaintextAndHmacAndPadding[nPlaintextAndHmacAndPadding-2 : nPlaintextAndHmacAndPadding]

	n := reversePaddingMap[lastByte]
	m := (16 - n)
	plaintextAndHmac = plaintextAndHmacAndPadding[0 : nPlaintextAndHmacAndPadding-2*m]
	nplaintextAndHmac := len(plaintextAndHmac)
	plainText = plaintextAndHmac[0 : nplaintextAndHmac-64]

	fmt.Println(hexToBin(plainText))
}
