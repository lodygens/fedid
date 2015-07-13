# Identity Federator


The Identity federator service permits user connection using different
identity providers.

## Introduction

This application launches an HTTPS server protecting an ``/apps`` path.
Users must present valid credentials to access that protected path.

Credentials may be:
* X509 certificate
* an external identity provided by an OAuth server

## Requirements


The application is written in [Go language](http://golang.org/ "Go").

This expects some external packages:

* github.com/apexskier/httpauth
* github.com/gorilla/mux
* golang.org/x/oauth2

One can easily installs them :

```
$> go get github.com/apexskier/httpauth github.com/gorilla/mux golang.org/x/oauth2 
```


## Configuration


The application needs a [Json](http://json.org/ "Json") configuration file.

This file may be found from :

* command line parameter (e.g.: ``$> fedid /home/user/conf/myconf.json``)
* ../conf/fedid.json (relative to the binary path)
* /etc/fedid.json

### Configuration variables

Some variables may be set in the configuration file.

Goal             | Name        |  Requirement | Comments
-----------------|-------------|--------------|---------
Logger level     | loggerlevel |  *Optionnal*   | Possible values: ``finest``, ``debug``, ``config``, ``info`` (**default**), ``warn``, ``error``, ``fatal``
Path containing CA certificates| cacertpath  | *Optionnal*  | If not set, users won't be able to authenticate using X509 certificate
Server certificate path | certpath | **Required** | Program exits, if not set
Server private key path | keypath | **Required** | Program exits, if not set
Listened HTTPS port | portnumber  |  *Optionnal*   | Default: 4325
An array containing OAuth servers configuration | OAuthServers | *Optionnal* | If not set, users won't be able to authenticate using any external OAuth server


The "OAuthServers" variable is an array containing OAuth server configurations.
All OAuth server configuration variables are **required** and come from the OAuth server console, but **name**. That last must be set but its content is free.  

As example, one can find detailed instructions for the [Google OAuth service configuration](https://developers.google.com/identity/protocols/OAuth2/ "Google OAuth service configuration").


OAuth server configuration variables are listed below.

Goal              | Name        
------------------|-------------
Server name       | name 
Client identifier | clientid 
Client secret     | clientsecret
OAuth redirection | redirecturl
OAuth URL         | authurl
Token URL         |	tokenurl


**Please note that name must end the ``redirecturl`` variable. This is how the application retrieve the OAuth server to use.**

Example:
if name is ``google``, then the redirect URL must end with ``/google``. It must be something like 
```
https://myserver:myPort/aPath/google
https://myserver:myPort/google
```


### Configuration example

```
{
	"loggerlevel"      : "debug",
	"cacertpath"         : "",
	"certpath"         : "",
	"keypath"          : "",
	"portNumber"       : "",
	"OAuthServers" : [
		{
 			"name"         : "google", 
 			"clientid"     : "",
			"clientsecret" : "",
			"redirecturl"  : "https://something/path/google",
			"authurl"      : "https://accounts.google.com/o/oauth2/auth",
			"tokenurl"     : "https://accounts.google.com/o/oauth2/token"
		}
	]
}
```

