# SSL Decryption/Spoofing
The app is able to decrypt SSL and spoof the remote site certificate. It acts as a MITM (sitting between client and remote server) decrypting HTTPS communication on-the-fly without a client spotting any difference.

## Disclaimer
This app was build solely for educational purposes. I did that to learn how the SSL encryption can be done. Author doesn't take any responsibility for misuse of this project.

## Prerequisites
 * Client must have the self-signed CA cert installed in Chrome/system
 * Client must have set the transparent (system/browser) proxy pointing at this app

## Details 
 * See `conf/configuration.go` for configuration options
 * In default the transparent proxy runs on 0.0.0.0:8080
 * In default the internal web server for SSL spoofing runs on 0.0.0.0:8443

## Setup
Generate certification authority (https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/)
1) `openssl genrsa -des3 -out myCA.key 2048`
2) `openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem` 
3) Configure the app to use these generated key and cert
4) Run the app
5) Import the myCA.pem into [Chrome](chrome://settings/security) under `Trusted Root Certification Authorities` (windows) or into the key-chain (Mac) - [More details can be found here](https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/)
6) Setup the HTTPS proxy (e.g. using [SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif?hl=en))
7) Test going to an HTTPS site and check the certificate details. They should resemble what is in `crypto/spoof.go#spoofCertificate`

## How do I find if it's working?
 * HTTPS pages render fine in the chrome browser (no security warning)
 * After clicking the small lock icon next to the domain in the address bar and selecting Certificate option you should see the spoofed cert
 * Logs of the app should show connections going through

## Sources used during the implementation
* https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/
* https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
