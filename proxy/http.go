package proxy

import (
	"github.com/elazarl/goproxy"
	"github.com/spf13/viper"
	"net"
	"net/http"
	"ssl-decryption/conf"
	"ssl-decryption/session"
)

func StartProxy(ss *session.Store) error {
	proxy := goproxy.NewProxyHttpServer()
	proxyHost := viper.GetString(conf.ProxyServerHost)
	dialer := &net.Dialer{}
	wsHost := viper.GetString(conf.WebServerHost)

	proxy.ConnectDial = func(network string, addr string) (net.Conn, error) {
		conn, err := dialer.Dial("tcp", wsHost)
		if err != nil {
			return nil, err
		}

		// Save session details under the ephemeral port key
		ephemeralPort := conn.LocalAddr().(*net.TCPAddr).Port
		go ss.PutSession(ephemeralPort, session.Session{Address: addr})

		return conn, err
	}

	return http.ListenAndServe(proxyHost, proxy)
}
