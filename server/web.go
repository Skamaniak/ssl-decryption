package server

import (
	"crypto/tls"
	"fmt"
	"github.com/spf13/viper"
	"io"
	"net"
	"net/url"
	"regexp"
	"ssl-decryption/conf"
	"ssl-decryption/crypto"
	"ssl-decryption/session"
)

func getIndex(arr []string, itm string) int {
	for i, v := range arr {
		if v == itm {
			return i
		}
	}
	return -1
}

type scanningWriter struct {
	inner          io.Writer
	extractorRegex *regexp.Regexp
}

func (c scanningWriter) Write(p []byte) (n int, err error) {
	match := c.extractorRegex.FindStringSubmatch(string(p))
	ind := getIndex(c.extractorRegex.SubexpNames(), "extract")
	if ind >= 0 && len(match) >= ind+1 {
		q, err := url.QueryUnescape(match[ind])
		if err == nil {
			fmt.Printf("Found content matching extractor: %v\n", q)
		}
	}

	return c.inner.Write(p)
}

func pumpData(to net.Conn, from net.Conn, dataTransferred chan int64) {
	//TODO move this to some more convenient place
	ce := viper.GetString(conf.ContentExtractionRule)
	writer := scanningWriter{
		inner:          to,
		extractorRegex: regexp.MustCompile(ce),
	}

	//TODO add net.Con.SetDeadline?
	written, err := io.Copy(writer, from)
	if err != nil {
		fmt.Println(err)
	}
	dataTransferred <- written
	close(dataTransferred)
}

func sum(c chan int64) int64 {
	var sum int64
	for {
		data, more := <-c
		sum = sum + data
		if !more {
			return sum
		}
	}
}

// Connection
type Connection struct {
	ConnFromProxy net.Conn
	ConnToRemote  net.Conn
	Address       string
}

func (c *Connection) String() string {
	return fmt.Sprintf("%v to %v", c.ConnFromProxy.LocalAddr(), c.Address)
}

func (c *Connection) pump() {
	fmt.Printf("Starting %v\n", c.String())
	defer func() { _ = c.ConnFromProxy.Close() }()
	defer func() { _ = c.ConnToRemote.Close() }()

	upload := make(chan int64)
	go pumpData(c.ConnToRemote, c.ConnFromProxy, upload)

	download := make(chan int64)
	go pumpData(c.ConnFromProxy, c.ConnToRemote, download)

	dataTransferred := sum(download) + sum(upload)
	fmt.Printf("Closing %v, transferred %d bytes\n", c.String(), dataTransferred)
}

// WebServer
type WebServer struct {
	certSpoofer *crypto.CertSpoofer
}

func NewWebServer() (*WebServer, error) {
	spoofer, err := crypto.NewCertSpoofer()
	if err != nil {
		return nil, err
	}
	return &WebServer{certSpoofer: spoofer}, nil
}

func (_ *WebServer) handleConnection(ss *session.Store, connFromProxy net.Conn) {
	ephemeralProxyPort := connFromProxy.RemoteAddr().(*net.TCPAddr).Port
	sess := <-ss.GetSession(ephemeralProxyPort)
	tlsConf := &tls.Config{}
	connToRemote, err := tls.Dial("tcp", sess.Address, tlsConf)
	if err != nil {
		fmt.Println("failed to dial "+sess.Address, err)
		return
	}

	connection := Connection{
		Address:       sess.Address,
		ConnFromProxy: connFromProxy,
		ConnToRemote:  connToRemote,
	}

	connection.pump()
}

func (ws *WebServer) returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ws.certSpoofer.GenerateSpoofedServerCertificate(helloInfo.ServerName)
}

func (ws *WebServer) StartServer(ss *session.Store) error {
	config := &tls.Config{
		GetCertificate: ws.returnCert,
	}
	wsHost := viper.GetString(conf.WebServerHost)
	fmt.Println("Starting internal TCP server on", wsHost)
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
		go ws.handleConnection(ss, connFromProxy)
	}

	return nil
}
