package server

import (
	"crypto/tls"
	"fmt"
	"github.com/spf13/viper"
	"io"
	"net"
	"ssl-decryption/conf"
	"ssl-decryption/crypto"
	"ssl-decryption/session"
)

func pumpData(from net.Conn, to net.Conn) {
	_, _ = io.Copy(from, to)
}

func handleConnection(ss *session.Store, connFromProxy net.Conn) {
	ephemeralProxyPort := connFromProxy.RemoteAddr().(*net.TCPAddr).Port
	sess := <-ss.GetSession(ephemeralProxyPort)
	tlsConf := &tls.Config{}
	connectionToRemote, err := tls.Dial("tcp", sess.Address, tlsConf)
	if err != nil {
		fmt.Println("failed to dial "+sess.Address, err)
		return
	}

	go pumpData(connFromProxy, connectionToRemote)
	go pumpData(connectionToRemote, connFromProxy)
}

func StartServer(ss *session.Store) error {
	config := &tls.Config{
		GetCertificate: returnCert,
	}
	wsHost := viper.GetString(conf.WebServerHost)
	ln, err := tls.Listen("tcp", wsHost, config)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	for {
		connFromProxy, err := ln.Accept()
		if err != nil {
			fmt.Println("failed to accept connection", err)
			break
		}
		go handleConnection(ss, connFromProxy)
	}

	return nil
}

func returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return crypto.GenerateSpoofedServerCertificate(helloInfo.ServerName)
}
