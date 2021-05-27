package main

import(
	"hash"
	"encoding/json"
	"encoding/base64"
	"strings"
	"fmt"
	"os"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"bufio"
)

func base64urlDecode(toDecode string) (string, bool) {
		result, err := base64.RawURLEncoding.DecodeString(toDecode)
		if err != nil {
			return string(result), false
		}
		return string(result), true
}

func base64urlEncode(toEncode string) string {
		result := base64.RawURLEncoding.EncodeToString([]byte(toEncode))
		return string(result)
}

func parse_token(token string) ([]string, bool) {
	var many_points int
	for _, v := range token {
		if string(v) == "." {
			many_points++
		}
	}
	if many_points == 2 {
		result := strings.Split(token, ".")
		return result, true
	}
	return nil, false
}

func decrypt_token(token string) (string, string, bool) {
	token_parse, err := parse_token(token)
	if err == false {
		return "" , "", false
	}
	head, headErr := base64urlDecode(token_parse[0])
	payload, payloadErr:= base64urlDecode(token_parse[1])
	if payloadErr == false && headErr == false {
		error("token")
	}
	if string(payload[0]) != "{" && string(payload[0:1]) != "}" {
		error("token")
	}
	if string(head[0]) != "{" && string(head[0:1]) != "}" {
		error("token")
	}
	return string(head),string(payload), true
}

func error(reason string) {
	help()
	if reason == "token" {
		fmt.Println("[-] error, invalid token.")
		os.Exit(1)
	}
	if reason == "wordlist" {
		fmt.Println("[-] error, invalid wordlist.")
		os.Exit(1)
	}
	if reason == "hash" {
		fmt.Println("[-] error, invalid hash.")
	}
}

func hmacEncode(token, key, hashtype string) string {
	var mac hash.Hash
	if hashtype == "HS256" {
		mac = hmac.New(sha256.New, []byte(key))
	}
	if hashtype == "HS384" {
		mac = hmac.New(sha512.New384, []byte(key))
	}
	if hashtype == "HS512" {
		mac = hmac.New(sha512.New, []byte(key))
	}
	mac.Write([]byte(token))
	result := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	result = strings.Replace(result, "=", "", -1)
	return result
}

func CreateJWT(head, payload, key string) string {
	hash := getAlg(head)
	head = base64urlEncode(head)
	payload = base64urlEncode(payload)
	token := head + "." + payload
	result := token + "." + hmacEncode(token, key, hash)
	return result
}

func bruteforce(head, payload string, wordlist, token string) (string,bool) {
	file, err := os.Open(wordlist)
	if err != nil{
		error("wordlist")
	} else {
		fileScanner := bufio.NewScanner(file)
		fileScanner.Split(bufio.ScanLines)
		for fileScanner.Scan() {
			if CreateJWT(head, payload, string(fileScanner.Text())) == token {
			return string(fileScanner.Text()), true
			}
		}
	}
	return "", false
}

func Split(r rune) bool {
	return r == ',' || r == ':'
}

type JWT_Header struct {
    Alg string `json: "alg"`
    Typ string `json: "typ"`
}

func getAlg(head string) string {
	header := JWT_Header{}
	_ = json.Unmarshal([]byte(head), &header)
	return header.Alg
}

func help() {
	fmt.Println("Usage : " + os.Args[0] + " -jwt JWT_TOKEN -w wordlist")
	os.Exit(0)
}