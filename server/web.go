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
	"sync/atomic"
)

func pumpData(from net.Conn, to net.Conn, dataTransferred chan int64) {
	//TODO add net.Con.SetDeadline?
	written, err := io.Copy(from, to)
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

	upload := make(chan int64)
	go pumpData(c.ConnFromProxy, c.ConnToRemote, upload)

	download := make(chan int64)
	go pumpData(c.ConnToRemote, c.ConnFromProxy, download)

	dataTransferred := sum(upload) + sum(download)
	fmt.Printf("Closing %v, transferred %d\n", c.String(), dataTransferred)
}

func handleConnection(ss *session.Store, connFromProxy net.Conn) {
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

	var counter int32
	for {
		connFromProxy, err := ln.Accept()
		if err != nil {
			fmt.Println("failed to accept connection", err)
			break
		}
		go func() {
			atomic.AddInt32(&counter, 1)
			handleConnection(ss, connFromProxy)
			atomic.AddInt32(&counter, -1)
			fmt.Printf("Current connection count is %d\n", counter)
		}()
	}

	return nil
}

func returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return crypto.GenerateSpoofedServerCertificate(helloInfo.ServerName)
}
