package main

import "fmt"

func main() {
	//test2()
	generator := newDigSshKeyGenetorDefault()

	private, public, err := generator.Generate()

	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Private Key: ", private)
	fmt.Println("Public Key: ")
	fmt.Println(public)

	regentPublickeyFromPrivateKey(private)
}
