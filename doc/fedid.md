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
=============

This needs a [Json](http://json.org/ "Json") configuration file.

This file may be found:

* from command line parameter. 
  One can provide the json file path as parameter:
  ``$> fedid myconf.json``
* from ../conf/fedid.json (relative to the binary path)
* from /etc/fedid.json
