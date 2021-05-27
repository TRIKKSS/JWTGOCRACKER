package main

import(
	"fmt"
	"os"
	"time"
)

func main(){
	fmt.Println("~JWTGOCRACKER 1.0~")
	var token string
	var wordlist string
	for i ,arg := range os.Args {
		if arg == "-jwt" {
			token = os.Args[i + 1]
		}
		if arg == "-w" {
			wordlist = os.Args[i + 1]
		}
		if arg == "-h" {
			help()
		}
	}
	decryptedHead, decryptedPayload, decrTokenErr := decrypt_token(token)
	if decrTokenErr == false {
		error("token")
	}
	getAlg(decryptedHead)
	start := time.Now()
	crack, err := bruteforce(decryptedHead, decryptedPayload, wordlist, token)
	if err == true{
		elapsed := time.Since(start)
		fmt.Println("[+] password crack !")
		fmt.Println("[+] the secret key is " + crack)
		fmt.Printf("[*] execution time : %s", elapsed)
	} else {
		fmt.Println("[-] can't crack this JWT.")
	}
}