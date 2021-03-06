// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"google.golang.org/appengine"
)

var (
	demo_domain_name  string
	demo_appspot_name string

	key_ec256   []byte
	certs_ec256 []byte

	key_rsa   []byte
	certs_rsa []byte
	
	key_ec256_invalid   []byte
	certs_ec256_invalid []byte
	
	old_ocsp  []byte
)

type Config struct {
	DemoDomainName  string `json:"demo_domain"`
	DemoAppSpotName string `json:"demo_appspot"`
	EC256KeyFile    string `json:"ec256_key_file"`
	EC256CertFile   string `json:"ec256_cert_file"`
	RSAKeyFile      string `json:"rsa_key_file"`
	RSACertFile     string `json:"rsa_cert_file"`
	EC256InvalidKeyFile    string `json:"ec256_invalid_key_file"`
	EC256InvalidCertFile   string `json:"ec256_invalid_cert_file"`
	
	OldOCSPFile   string `json:"old_ocsp_file"`
}

func init() {
	var config Config
	file, err := os.Open("config.json")
	defer file.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(file)
	jsonParser.Decode(&config)

	demo_domain_name = config.DemoDomainName
	demo_appspot_name = config.DemoAppSpotName

	key_ec256, _ = ioutil.ReadFile(config.EC256KeyFile)
	certs_ec256, _ = ioutil.ReadFile(config.EC256CertFile)
	key_rsa, _ = ioutil.ReadFile(config.RSAKeyFile)
	certs_rsa, _ = ioutil.ReadFile(config.RSACertFile)
	key_ec256_invalid, _ = ioutil.ReadFile(config.EC256InvalidKeyFile)
	certs_ec256_invalid, _ = ioutil.ReadFile(config.EC256InvalidCertFile)
	
	old_ocsp, _ = ioutil.ReadFile(config.OldOCSPFile)
}

func main() {
	http.HandleFunc("/cert/", certHandler)
	http.HandleFunc("/sxg/", signedExchangeHandler)
	http.HandleFunc("/", defaultHandler)
	appengine.Main()
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello, world!")
}
