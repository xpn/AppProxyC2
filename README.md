# AppProxyC2

This repo contains a simple POC to show how to tunnel traffic through Azure Application Proxy.

**NOTE: This is not designed to be compiled and run on an engagement, it is here only to show how the protocol works alongside the blog post and to allow custom implementations to be created.**

The blog post accompanying this repo can be found [here](https://www.trustedsec.com/blog/).

### ./AppProxyC2CertificateCreator

This is a simple tool which allows us to create the client certificate required for mutual TLS authentication when running AppProxyC2, for example:

Generate your security token by navigating to:

```
https://login.microsoftonline.com/common/oauth2/authorize?resource=https%3A%2F%2Fproxy.cloudwebappproxy.net%2Fregisterapp&client_id=55747057-9b5d-4bd4-b387-abf52a8bd489&response_type=code&haschrome=1&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&client-request-id=2b10921b-e812-5111-ad0e-1401b2f42bdc&prompt=login&x-client-SKU=PCL.Desktop&x-client-Ver=3.19.8.16603&x-client-CPU=x64&x-client-OS=Microsoft+Windows+NT+10.0.19041.0
```

Take the returned `code` parameter given after authentication and use this to generate a certificate with:

```
AppProxyC2CertificateCreator.exe output.pfx [CODE TOKEN HERE]
```

### ./AppProxyC2

The main AppProxyC2 POC project (x86). This handles the bootstrapping, Service Bus and ExternalC2 protocols to funnel traffic through Application Proxy by acting as a connector. As Application Proxy is an inbound protocol, ensure that this is up and running before starting the Team Server side ExternalC2 script.

### ./Python

Contains the Team Server side implementation of External C2 in Python.
