package conf

import (
	"github.com/spf13/viper"
)

const CaCertLocation = "CA_CERTIFICATE_LOCATION"
const CaKeyLocation = "CA_KEY_LOCATION"
const CaKeyPassword = "CA_KEY_PASSWORD"
const SpoofedCertValidityYears = "SPOOFED_CERT_VALIDITY_YEARS"
const WebServerHost = "WEB_SERVER_HOST"
const ProxyServerHost = "PROXY_SERVER_HOST"

func InitConfig() {
	viper.AutomaticEnv()

	viper.SetDefault(CaCertLocation, "assets/myCA.pem")
	viper.SetDefault(CaKeyLocation, "assets/myCA.key")
	viper.SetDefault(CaKeyPassword, "changeit")

	viper.SetDefault(WebServerHost, "0.0.0.0:8443")
	viper.SetDefault(ProxyServerHost, "0.0.0.0:8080")

	viper.SetDefault(SpoofedCertValidityYears, 1)
}
