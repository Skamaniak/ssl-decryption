package main

import (
	"ssl-decryption/conf"
	"ssl-decryption/proxy"
	"ssl-decryption/server"
	"ssl-decryption/session"
)

func main() {
	conf.InitConfig()
	sessionStore := session.NewSessionStore()

	go func() {
		srvr, _ := server.NewWebServer()
		_ = srvr.StartServer(sessionStore)
	}()

	_ = proxy.StartProxy(sessionStore)
}
