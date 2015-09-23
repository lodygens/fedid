package main

/*
 Copyrights     : CNRS
 Author         : Oleg Lodygensky

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.

*/

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/oauth2"
	"io/ioutil"
	"os"
)

/**
 * This is the OAuth ID token string representation
 */
const OAUTH_IDTOKEN_NAME = "id_token"

// This contains the OAuth2 configuration and the API to retreive expected 
// informations from OAuth server (mail, login etc.)
type OAuth2Config struct {
	Config    *oauth2.Config
	ApiUrl    string
}

/**
 * This creates a new certificates pool that can be used to validate user
 * certificate and synchronizes concurrent access to that pool.
 * This is expected since ServerHTTP run on their own goroutine
 * @param path is the path to retrieve CA certificates 
 * @param c is the channel to write to
 * @see #PopulateCertPool(string)
 */
func CaCertPoolManager(path string, c chan *x509.CertPool) {

	var logger = NewPrefixed("security#CaCertPoolManager")

	caCertPool := new(x509.CertPool)
	caCertPool, err := populateCertPool(path)
	if err != nil {
		logger.Fatal(err.Error())
	}

	for {
		select {
		case c <- caCertPool:
			logger.Finest("Written caCertPool: %v", len(caCertPool.Subjects()))
		}
	}
}


/**
 * This creates a new OAuth configuration and synchronizes concurrent access 
 * to that configuration.
 * This is expected since ServerHTTP run on their own goroutine
 * @param path is the path to retrieve CA certificates 
 * @param c is the channel to write to
 * @see #PopulateCertPool(string)
 */
//func OAuthConfigurationManager(clientid, clientsecret, redirecturl, authurl, tokenurl, apiurl string, c chan *oauth2.Config) {
func OAuthConfigurationManager(clientid, clientsecret, redirecturl, authurl, tokenurl, apiurl string, c chan *OAuth2Config) {

	var logger = NewPrefixed("security#OAuthConfigurationManager")

	oauthConfig := new (OAuth2Config)
	oauthConfig.ApiUrl  = apiurl
	oauthConfig.Config = new (oauth2.Config)
	oauthConfig.Config.ClientID     = clientid
	oauthConfig.Config.ClientSecret = clientsecret
	oauthConfig.Config.Scopes       = []string{"email"}
	oauthConfig.Config.RedirectURL  = redirecturl
	oauthConfig.Config.Endpoint     = oauth2.Endpoint{
			AuthURL:  authurl,
			TokenURL: tokenurl,
		}

	for {
		select {
		case c <- oauthConfig:
			logger.Finest("Written OAuthconf : %v", oauthConfig)
		}
	}
}


/**
 * This retrieves all CA certificates from given path
 * If path denotes a directory, all files are added to the CertPool;
 * subdirectories are not traveled.
 * @param caRootPath is either a file or a directory
 * @return an x509.CertPool containing all CA certificates or nil on error
 * @return last error if any, or nil
 */
func populateCertPool(caRootPath string) (caRootPool *x509.CertPool, err error) {

	var logger = NewPrefixed("security#PopulateCertPool")

	caRootPool = x509.NewCertPool()
	var caRootFiles []os.FileInfo

	caRootInfo, err := os.Lstat(caRootPath)
	if err != nil {
		return nil, err
	}

	if caRootInfo.IsDir() == true {
		const slash = "/"
		if caRootPath[len(caRootPath)-1] != slash[0] {
			caRootPath = caRootPath + slash
		}
		caRootFiles, err = ioutil.ReadDir(caRootPath)
		if err != nil {
			return nil, err
		}

		for _, file := range caRootFiles {

			if file.IsDir() {
				continue
			}

			buf, err := ioutil.ReadFile(caRootPath + file.Name())
			if err != nil {
				return nil, err
			}

			caRootPool.AppendCertsFromPEM(buf)
			if caRootPool.AppendCertsFromPEM(buf) {
				logger.Finest("Parsed : %v\n", file.Name())
			}
		}
	} else {
		var buf []byte
		if buf, err = ioutil.ReadFile(caRootPath); err != nil {
			return nil, err
		}

		caRootPool.AppendCertsFromPEM(buf)
		if caRootPool.AppendCertsFromPEM(buf) {
			logger.Finest("Parsed : %v\n", caRootPath)
		}
	}

	return caRootPool, nil
}

/**
 * This retrieves certificate from PEM files
 * @param certPath is the PEM path containing the certificate
 * @param keyPath is the PEM path containing the private key
 * @return an x509.Certficate or nil on error
 * @return last error if any, or nil
 */
func cerficateFromPEMs(certPath, keyPath string) (cert *x509.Certificate, err error) {

	var logger = NewPrefixed("security#CerficateFromPEMs")
	logger.Debug("Cert: %v ; Key : %v", certPath, keyPath)
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	logger.Debug("len(KeyPair.Certificate) = %v\n", len(keyPair.Certificate))

	return x509.ParseCertificate(keyPair.Certificate[0])
}

/**
 * This retrieves certificate from PEM files
 * @param certPath is the PEM path containing the certificate
 * @param keyPath is the PEM path containing the private key
 * @return an tls.Certficate or nil on error
 * @return last error if any, or nil
 */
func TLSCerficateFromPEMs(certPath, keyPath string) (cert *tls.Certificate, err error) {
	var logger = NewPrefixed("security#TLSCerficateFromPEMs")
	ca_b, err := ioutil.ReadFile(certPath)
	if err != nil {
		logger.Warn(err.Error())
	}
	priv_b, err := ioutil.ReadFile(keyPath)
	if err != nil {
		logger.Warn(err.Error())
	}
	priv, err := x509.ParsePKCS1PrivateKey(priv_b)
	if err != nil {
		logger.Warn(err.Error())
	}

	cert = new(tls.Certificate)
	cert.Certificate = [][]byte{ca_b}
	cert.PrivateKey  = priv
	cert.Leaf, err = cerficateFromPEMs(certPath, keyPath)
	return cert, err
}

func TLSConfig(cert *tls.Certificate, caCertPool *x509.CertPool) (config *tls.Config) {

	config = new(tls.Config)

		//		RootCAs:      caRootPool,
	config.ClientCAs =    caCertPool
	config.Certificates= []tls.Certificate{*cert}
		//MinVersion=   tls.VersionSSL30, //don't use SSLv3, https://www.openssl.org/~bodo/ssl-poodle.pdf
	config.MinVersion= tls.VersionTLS10
		//MinVersion=   tls.VersionTLS11,
		//MinVersion=   tls.VersionTLS12,
		//		ClientAuth= tls.VerifyClientCertIfGiven,
	config.ClientAuth= tls.RequestClientCert
		//		ClientAuth= tls.RequireAnyClientCert,
		//		ClientAuth= tls.RequireAndVerifyClientCert,
	config.Rand = rand.Reader
	config.SessionTicketsDisabled = false

	return config
}
