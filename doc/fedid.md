# Identity Federator


The Identity federator service permits user connection using different
identity providers.

## Introduction

This application launches an HTTPS server protecting an ``/apps`` path.
Users must present valid credentials to access that protected path.

## Requirements


This is written in [Go language](http://golang.org/ "Go").

This expects some external packages:

* github.com/apexskier/httpauth
* github.com/gorilla/mux
* golang.org/x/oauth2

One can easily installs them :

```
$> go get github.com/apexskier/httpauth github.com/gorilla/mux golang.org/x/oauth2 
```


## Configuration


This needs a [Json](http://json.org/ "Json") configuration file.

This file may be found from :

* command line parameter (e.g.: ``$> fedid /home/user/conf/myconf.json``)
* ../conf/fedid.json (relative to the binary path)
* /etc/fedid.json

### Configuration variables

You may need to set some variables in the configuration file.

Goal             | Name        |  Requirement | Comments  | Default
-----------------|-------------|--------------|-----------|--------
Logger level     | loggerlevel |  *Optionnal*   | Possible values: ``finest``, ``debug``, ``config``, ``info``, ``warn``, ``error``, ``fatal`` | info
Path containing CA certificates| cacertpath  | *Optionnal*  | If not set, users won't be able to authenticate using X509 certificates | n/a
Server certificate path | certpath | **Required** | | n/a
Server private key path | keypath | **Required** | | n/a
HTTPS port to listen| portnumber  |  *Optionnal*   |           | 4325
An array containing OAuth servers configuration | OAuthServers | *Optionnal* | | n/a


The "OAuthServers" variable is an array containing OAuth server configurations.
All OAuth server configuration variables are **required** and listed below

Goal              | Name        
------------------|-------------
Server name       | name 
Client identifier | clientid 
Client secret     | clientsecret
OAuth redirection | redirecturl
OAuth URL         | authurl
Token URL         |	tokenurl

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
			"redirecturl"  : "",
			"authurl"      : "https://accounts.google.com/o/oauth2/auth",
			"tokenurl"     : "https://accounts.google.com/o/oauth2/token"
		}
	]
}
```

