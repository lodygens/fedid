package main

/*
 * Copyrights     : CNRS
 * Author         : Oleg Lodygensky
 * Acknowledgment : XtremWeb-HEP is based on XtremWeb 1.8.0 by inria : http://www.xtremweb.net/
 * Web            : http://www.xtremweb-hep.org
 *
 *      This file is part of XtremWeb-HEP.
 *
 *    XtremWeb-HEP is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    XtremWeb-HEP is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with XtremWeb-HEP.  If not, see <http://www.gnu.org/licenses/>.
 *
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
func OAuthConfigurationManager(clientid, clientsecret, redirecturl, authurl, tokenurl string, c chan *oauth2.Config) {

	var logger = NewPrefixed("security#OAuthConfigurationManager")

	oauthConfig := new (oauth2.Config)
	oauthConfig.ClientID     = clientid
	oauthConfig.ClientSecret = clientsecret
	oauthConfig.Scopes       = []string{"email"}
	oauthConfig.RedirectURL  = redirecturl
	oauthConfig.Endpoint     = oauth2.Endpoint{
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
