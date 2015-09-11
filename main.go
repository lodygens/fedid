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
	"crypto/md5"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/apexskier/httpauth"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

/**
 * This is the "/" URL
 */
const ROOTURL = "/"

/**
 * This is the OAuth redirect URL path
 */
const OAUTHURL = "/oauth2/"

/**
 * This is the protected application path
 */
const APPSURL = "/apps/"

/**
 * This is the Json Web Token URL
 */
const JWTURL = "/jwtcallback"

/**
 * This channels aims to transmit CA certificates pool to all goroutines
 */
var caChannel chan *x509.CertPool

/**
 * This stores channels to transmit OAuth configuration to all goroutines
 */
var oauthConfigurationChannels map[string]chan *oauth2.Config

var conf Configuration

var (
	backend        httpauth.GobFileAuthBackend
	httpAuthorizer httpauth.Authorizer
	roles          map[string]httpauth.Role
	backendfile    = "auth.gob"
)

type Configuration struct {
        LoggerLevel string
        CACertPath  string
        CertPath    string
        KeyPath     string
        PortNumber  string
        OAuthServers []OAuthServer
}

type OAuthServer struct {
    Name       string
    Clientid     string
    Clientsecret string
    RedirectUrl  string
    AuthUrl      string
    TokenUrl     string
}

/**
 * This is the standard main function
 */
func main() {

	SetLoggerLevel(conf.LoggerLevel)
	var logger = NewPrefixed("main#main")

	confFilePath := ""
	baseName := filepath.Base(os.Args[0])
	jsonConfFileName := baseName + ".json"
	dirName, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Fatal("%v", err)
	}

	if len(os.Args) > 1 {
		confFilePath = os.Args[1]
	}
	jsonConfFile, err := os.Open(confFilePath)
	if err != nil {
		logger.Debug("Can't find json conf file : %v", confFilePath)
		confFilePath, err = filepath.Abs(dirName + "/../conf/" + jsonConfFileName)
	}
	jsonConfFile, err = os.Open(confFilePath)
	if err != nil {
		logger.Debug("Can't find json conf file : %v", confFilePath)
		confFilePath = "/etc/" + jsonConfFileName
	}
	jsonConfFile, err = os.Open(confFilePath)
	if err != nil {
		logger.Fatal("Can't find json conf file : %v", confFilePath)
	}

	decoder := json.NewDecoder(jsonConfFile)
	err = decoder.Decode(&conf)
	if err != nil {
		fmt.Println("error:", err)
	}

	logger.Info("%v", conf)

	if conf.CACertPath == "" {
		logger.Warn("CA certificate path is not set: X509 credentials refused")
	}
	if conf.CertPath == "" {
		logger.Fatal("server certificate path is not set")
	}
	if conf.KeyPath == "" {
		logger.Fatal("server key path is not set")
	}

	oauthConfigurationChannels = make(map[string]chan *oauth2.Config)
	hostName := GetLocalHostName()

	for _, s := range conf.OAuthServers {

		if	len(s.Name) < 1 ||
			len(s.Clientid) < 1 ||
			len(s.Clientsecret) < 1 ||
			len(s.RedirectUrl) < 1 ||
			len(s.AuthUrl) < 1 ||
			len(s.TokenUrl) < 1 {

			logger.Warn("Ignoring %v : incorrect configuration", s.Name)
			continue
		}
		//
		// start OAuth config manager
		//
		logger.Info("s.Name = %v", s.Name)
		oauthConfigurationChannels[s.Name] = make(chan *oauth2.Config)
		go OAuthConfigurationManager(
			s.Clientid,
			s.Clientsecret,
			s.RedirectUrl,
			s.AuthUrl,
			s.TokenUrl,
			oauthConfigurationChannels[s.Name])
	}

	//
	// start CA cert pool manager
	//
	var caCertPool *x509.CertPool
	caChannel = nil
	caCertPool = nil

	if conf.CACertPath != "" {
		caChannel = make(chan *x509.CertPool)
		go CaCertPoolManager(conf.CACertPath, caChannel)

		//
		// get CA cert pool
		//
		caCertPool := <-caChannel
		logger.Debug("CA pool length = %v", len(caCertPool.Subjects()))
	}

	//
	// Retrieve certificate
	//
	cert, err := TLSCerficateFromPEMs(conf.CertPath, conf.KeyPath)
	if err != nil {
		logger.Fatal(err.Error())
	}

	logger.Debug("serverCert.Subject = %v", cert.Leaf.Subject)
	logger.Debug("serverCert.Issuer  = %v", cert.Leaf.Issuer)

	//
	// Verify cert against known CA
	//
	if caCertPool != nil {
		vOpts := x509.VerifyOptions{Roots: caCertPool}
		_, err = cert.Leaf.Verify(vOpts)
		if err != nil {
			logger.Warn("failed to parse server certificate: " + err.Error())
		}
	}

	tlsConfig := TLSConfig(cert, caCertPool)

	os.Create(backendfile)
	defer os.Remove(backendfile)
	backend, err = httpauth.NewGobFileAuthBackend(backendfile)
	if err != nil {
		logger.Fatal("can't create backend %v", err)
	}

	// create some default roles
	roles = make(map[string]httpauth.Role)
	roles["user"] = 30
	roles["admin"] = 80
	httpAuthorizer, err = httpauth.NewAuthorizer(backend, []byte("cookie-encryption-key"), "user", roles)

	// set up routers and route handlers
	r := mux.NewRouter()
	//	r.HandleFunc("/", appsPage).Methods("GET") // authorized page
	r.HandleFunc("/logout", handleLogout)
	r.HandleFunc(ROOTURL, X509Authenticator)
	r.HandleFunc(OAUTHURL, OAuthenticationPage)
	for _, s := range conf.OAuthServers {
		r.HandleFunc(OAUTHURL + s.Name, OAuthAuthenticator)
	}
	r.HandleFunc(APPSURL, appsPage)
	r.HandleFunc(JWTURL, JWTAuthenticator)

	server := http.Server{Addr: hostName + ":" + conf.PortNumber, TLSConfig: tlsConfig, Handler: r}

	// start https
	logger.Info("Listening HTTPS : " + hostName + ":" + conf.PortNumber)

	server.ListenAndServeTLS(conf.CertPath, conf.KeyPath)
}

/**
 * This authenticates user providing X509 credential
 */
func X509Authenticator(writer http.ResponseWriter, request *http.Request) {

	logger := NewPrefixed("X509Authenticator")

	if caChannel == nil || len(request.TLS.PeerCertificates) < 1 {
		logger.Debug("No CA cert pool or no TLS peer certificate; redirect to OAuth page")
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}

	logger.Finest("Retrieving ca cert pool")
	caCertPool := <-caChannel
	logger.Finest("CA pool length = %v", len(caCertPool.Subjects()))

	logger.Debug("len(r.TLS.PeerCertificates) = %v", len(request.TLS.PeerCertificates))

	//	for i, c := range request.TLS.PeerCertificates {
	//		logger.Debug("request.TLS.PeerCertificates[%v].Subject = %v", i, c.Subject)
	//		logger.Debug("request.TLS.PeerCertificates[%v].Issuer = %v", i, c.Issuer)
	//		for j, a := range c.EmailAddresses {
	//			logger.Debug("request.TLS.PeerCertificates[%v].EmailAddresses[%v] = %v", i, j, a)
	//		}
	//	}
	logger.Finest("len(r.TLS.VerifiedChains) = %v", len(request.TLS.VerifiedChains))

	vOpts := x509.VerifyOptions{Roots: caCertPool}

	userCert := request.TLS.PeerCertificates[0]
	chains, err := userCert.Verify(vOpts)
	if err != nil {
		logger.Warn("failed to parse certificate: " + err.Error())
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}

	logger.Debug("shains = %v\n", chains)

	var user httpauth.UserData
	user.Username = userCert.Subject.CommonName + "#" + userCert.Issuer.CommonName
	user.Email = userCert.EmailAddresses[0]
	password := "we don't need the password"

	err = httpAuthorizer.Register(writer, request, user, password)
	logger.Debug("register err = %v", err)
	err = httpAuthorizer.Login(writer, request, user.Username, password, APPSURL)
	logger.Debug("login err = %v", err)
	if err != nil {
		logger.Debug ("err.Error = %v", err.Error())
	}

	if err == nil || err.Error() == "httpauth: already authenticated" {
		logger.Debug("00")
		http.Redirect(writer, request, APPSURL, http.StatusSeeOther)
	} else {
		logger.Debug("01")
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
	}

	logger.Debug("Fin")
}

/**
 * This authenticates user providing OAuth credential
 */
func OAuthAuthenticator(writer http.ResponseWriter, request *http.Request) {

	logger := NewPrefixed("OAuthAuthenticator")

	h := md5.New()
	io.WriteString(h, "The fog is getting thicker!")
	io.WriteString(h, "And Leon's getting larger!")
	i := fmt.Sprintf("%x", h.Sum(nil))
	logger.Debug("h.sum() = %v", i)

	logger.Debug("r.Method = %v", request.Method)
	logger.Debug("r.URL = %v", request.URL)
	p, _ := url.ParseQuery(request.URL.Path)
	p, err := url.ParseQuery(request.URL.RawQuery)

	if (err != nil) {
		logger.Warn("failed to find OAuth credentials: " + err.Error())
		OAuthenticationPage(writer, request)
		return
	}
	if (p == nil) || (p["code"] == nil) || (len(p["code"]) < 1) {
		logger.Warn("failed to find OAuth credentials (code not set)")
		OAuthenticationPage(writer, request)
		return
	}

	paths := strings.Split(request.URL.Path, "/")
	if len(paths) < 3 {
		logger.Warn("failed to retreive AOuth server")
		OAuthenticationPage(writer, request)
		return
	}

	oauthServerName := paths[len(paths)-1]

	//
	// Retrieve OAuth conf
	//
	logger.Finest("oauthConfigurationChannels[%v] = %v", oauthServerName, oauthConfigurationChannels[oauthServerName])

	if oauthConfigurationChannels[oauthServerName] == nil {
		logger.Debug("No OAuth conf channel for %v", oauthServerName)
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}

	oauthConf := <-oauthConfigurationChannels[oauthServerName]
	logger.Debug("config = %v", oauthConf)

	code := p["code"][0]
	token, err := oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		logger.Warn(err.Error())
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}

	if token != nil && token.Extra(OAUTH_IDTOKEN_NAME) == nil {
		logger.Warn("No OAuth id_token; redirect to OAuth page")
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}

	if oauthConf == nil {
		logger.Warn("No OAuth conf; redirect to OAuth page")
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}
	
	client := oauthConf.Client(oauth2.NoContext, token)

	if client == nil {
		logger.Warn("No OAuth client; redirect to OAuth page")
		http.Redirect(writer, request, OAUTHURL, HTTPCODE_UNAUTHORIZED)
		return
	}

	var body = make([]byte, 1024)

	clientResponse, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")

	logger.Debug("poeut")
	n, err := clientResponse.Body.Read(body)
	logger.Debug("poeut %v, %v", n, err)
	if err == nil {
		var user map[string]interface{}
		err = json.Unmarshal(body[:n], &user)
		logger.Info("user = %v", user)
		fmt.Fprint(writer, "<p>You are logged in as ", user["email"], "</p>")
	}
}

/**
 * This is a method of the interface X509Authenticator
 * This overrides Handler#ServeHTTP(ResponseWriter, *Request)
 */
func OAuthenticationPage(w http.ResponseWriter, r *http.Request) {

	logger := NewPrefixed("OAuthAuthenticationPage")

	if len(conf.OAuthServers) <= 0 {
		fmt.Fprint(w, "<p>No OAuth server available</p>")
		return
	}

	fmt.Fprint(w, "<p>You are not logged in</p><p>You still have a chance to connect using one of the following</p>")

	for _, s := range conf.OAuthServers {
		if oauthConfigurationChannels[s.Name] != nil {
			oauthConfig := <-oauthConfigurationChannels[s.Name]
			logger.Debug("OAuthconf = %v", oauthConfig)
			url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
			logger.Debug("OAuth URL = %v", url)
			fmt.Fprintf(w, "<p><a href='%v'>%v</a></p>", url, s.Name)
			fmt.Fprintf(w, "<p><a href='%v&MYPARAM=pouet'>pour voir %v</a></p>", url, s.Name)
		}
	}
}

/**
 * This is a method for the interface JWTAuthenticator
 * This overrides Handler#ServeHTTP(ResponseWriter, *Request)
 */
func JWTAuthenticator(w http.ResponseWriter, r *http.Request) {

	logger := NewPrefixed("JWTAuthenticator")

	h := md5.New()
	io.WriteString(h, "The fog is getting thicker!")
	io.WriteString(h, "And Leon's getting larger!")
	i := fmt.Sprintf("%x", h.Sum(nil))
	logger.Debug("h.sum() = %v", i)

	logger.Debug("r.Method = %v", r.Method)
	logger.Debug("r.URL = %v", r.URL)
	p, _ := url.ParseQuery(r.URL.Path)
	logger.Debug("ParseQuery(r.URL.Path) = %v", p)
	p, _ = url.ParseQuery(r.URL.RawQuery)
	logger.Debug("ParseQuery(r.URL.RawQuery) = %v", p)
	logger.Debug("len(p['code']) = %v", len(p["code"]))
	logger.Debug("p['code'] = %v", p["code"])
	logger.Debug("r.Header = %v", r.Header)
	logger.Debug("r.Close = %v", r.Close)
	//	logger.Debug("r.Host = %v", r.Host)
	logger.Debug("r.Form = %v", r.Form)
	logger.Debug("len(r.Form) = %v", len(r.Form))
	logger.Debug("r.PostForm = %v", r.PostForm)
	logger.Debug("len(r.PostForm) = %v", len(r.PostForm))
	logger.Debug("r.MultipartForm = %v", r.MultipartForm)
	logger.Debug("r.Trailer = %v", r.Trailer)
	logger.Debug("r.RemoteAddr = %v", r.RemoteAddr)
	logger.Debug("r.RequestURI = %v", r.RequestURI)
	//	logger.Debug("r.TLS = %v", r.TLS)
	for i, v := range r.Form {
		logger.Debug("r.Form[%v] = %v", i, v)
	}
}

func appsPage(writer http.ResponseWriter, request *http.Request) {
	logger := NewPrefixed("AppsPage")
	err := httpAuthorizer.Authorize(writer, request, true)
	logger.Debug("err = %v", err)
	if err != nil {
		fmt.Println(err)
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if user, err := httpAuthorizer.CurrentUser(writer, request); err == nil {
		type data struct {
			User httpauth.UserData
		}
		d := data{User: user}
		t, err := template.New("page").Parse(`
            <html>
            <head><title>Secret page</title></head>
            <body>
                <h1>Httpauth example<h1>
                {{ with .User }}
                    <h2>Hello {{ .Username }}</h2>
                    <p>Your role is '{{ .Role }}'. Your email is {{ .Email }}.</p>
                    <p>{{ if .Role | eq "admin" }}<a href="/admin">Admin page</a> {{ end }}<a href="/logout">Logout</a></p>
                {{ end }}
                <form action="/change" method="post" id="change">
                    <h3>Change email</h3>
                    <p><input type="email" name="new_email" placeholder="new email"></p>
                    <button type="submit">Submit</button>
                </form>
            </body>
            `)
		if err != nil {
			panic(err)
		}
		t.Execute(writer, d)
	}
}
func handleLogout(writer http.ResponseWriter, req *http.Request) {
	if err := httpAuthorizer.Logout(writer, req); err != nil {
		fmt.Println(err)
		// this shouldn't happen
		return
	}
	http.Redirect(writer, req, "/", http.StatusSeeOther)
}
