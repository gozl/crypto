package crypto_test

import (
	"fmt"
	"time"

	"github.com/gozl/crypto"
)

func ExampleHMACEncoder_Encode() {
	src := "this is a secret message"

	hashKey := crypto.GetBytes(32)
	blockKey := crypto.GetBytes(32)

	// pass in nil instead of blockKey if you don't need encryption
	encoder, err1 := crypto.NewHMACEncoder(hashKey, blockKey)
	if err1 != nil {
		fmt.Println(err1.Error())
	}

	encrypted, err2 := encoder.Encode("test1", []byte(src))
	if err2 != nil {
		fmt.Println(err2.Error())
	}

	var decrypted []byte
	err3 := encoder.Decode("test1", encrypted, &decrypted)
	if err3 != nil {
		fmt.Println(err3.Error())
	}

	fmt.Println("Original : " + src)
	//fmt.Println("Encoded  : " + string(encrypted))
	fmt.Println("Restored : " + string(decrypted))

	// Output:
	// Original : this is a secret message
	// Restored : this is a secret message
}

func ExampleHMACEncoder_DecodeWithTTL() {
	src := "this is a secret message"

	hashKey := crypto.GetBytes(32)
	blockKey := crypto.GetBytes(32)

	// pass in nil instead of blockKey if you don't need encryption
	encoder, _ := crypto.NewHMACEncoder(hashKey, blockKey)
	encrypted, _ := encoder.Encode("test1", []byte(src))

	time.Sleep(4 * time.Second)

	var decrypted []byte
	err := encoder.DecodeWithTTL("test1", 0, 2, encrypted, &decrypted)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(string(decrypted))
	}

	err2 := encoder.DecodeWithTTL("test1", 0, 5, encrypted, &decrypted)
	if err2 != nil {
		fmt.Println(err2.Error())
	} else {
		fmt.Println(string(decrypted))
	}

	// Output:
	// data has expired
	// this is a secret message
}
