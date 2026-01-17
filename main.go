package main

import (
	"fmt"
	"ecdsa-implementation/internal/ecdsa"
)

func main() {
	fmt.Println("Key derivation")
	// generate the private key
	sk, err := ecdsa.GenerateRandomScalar()
	if err != nil {
		fmt.Println("something went wrong")
	}

	// generate the public key
	pk := ecdsa.GeneratePublicKey(sk)
	
	fmt.Println("ECDSA Signature")

	// generate a message and convert to bytes
	message := "Hello world"
	messageBytes := []byte(message)

	// generate random k
	k, _ := ecdsa.GenerateRandomScalar()

	signature := ecdsa.SignMessage(messageBytes, pk, sk, k)

	fmt.Println("Signature: ", signature.S)
	fmt.Println("r from Signature: ", signature.R)


	fmt.Println("ECDSA Signature Verification")

	isValidSignature := ecdsa.VerifySignature(signature)

	fmt.Println("Is valid signature? ", isValidSignature)
}