package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/dchest/captcha"
)

// All the consts are here.
const HumanCookieName = "X-Uncensor-Human"
const HumanCookieDuration = 5 * time.Minute
const HumanCookieCheck = true

const MappingLocalLocation = "/var/mirrors/mirrors.json"
const MappingRemoteLocation = "http://localhost/mirrors.json"
const MappingUpdateInterval = 5 * time.Minute

const ByteBufferPoolSize = 20
const ByteBufferSize = 1 << 14

const GzipStreamsPoolSize = 20
const GzipCompressionLevel = 3

var remoteConfigFlag string

func init() {
	flag.StringVar(&remoteConfigFlag, "config-url", MappingRemoteLocation, "The URL to periodically fetch configuration information from.")
	flag.Parse()
}

func main() {
	// Don't care if this succeeds or not at this point.
	updateMirrorMappings(remoteConfigFlag, MappingLocalLocation)

	// Setup the primary server object.
	replacers := loadMirrorMappings(MappingLocalLocation)
	myHandler := &ProxyServer{
		BufferChan: make(chan []byte, ByteBufferPoolSize),
		GzipChan:   make(chan gzipPair, GzipStreamsPoolSize),
		Client: http.Client{
			CheckRedirect: noClientRedirect,
		},
		Captcha: &CaptchaContext{
			Generator:     captcha.Server(captcha.StdWidth, captcha.StdHeight),
			Epoch:         time.Now(),
			Key:           GenerateCaptchaKey(),
			ValidDuration: HumanCookieDuration,
		},
	}
	myHandler.SetConfigurations(replacers)

	// Setup the background mapping updater.
	go loopUpdateMirrorMappings(myHandler, remoteConfigFlag, MappingLocalLocation, MappingUpdateInterval)

	// Create a waitgroup to prevent the main thread from exiting.

	// Create the HTTP server
	httpServer := http.Server{
		Addr:           ":http",
		Handler:        myHandler,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		log.Fatal(httpServer.ListenAndServe())
	}()

	// Create the HTTPS server
	tlsConfig := &tls.Config{
		Certificates: nil,
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cfg, _ := myHandler.GetConfiguration(ch.ServerName); cfg != nil {
				if cfg.Certificate != nil {
					return cfg.Certificate, nil
				}
			}
			return nil, fmt.Errorf("Unable to find certificate for %v", ch)
		},
		NextProtos: []string{"http/1.1"},
	}
	secureServer := http.Server{
		Addr:           ":https",
		Handler:        myHandler,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      tlsConfig,
	}
	var secureListener net.Listener
	if secureLn, err := net.Listen("tcp", secureServer.Addr); err != nil {
		log.Fatal(err)
	} else {
		secureListener = tls.NewListener(tcpKeepAliveListener{secureLn.(*net.TCPListener)}, secureServer.TLSConfig)
	}

	log.Fatal(secureServer.Serve(secureListener))
}

// This is replicated from golang's server.go. This struct
// isn't exposed. But replicating it allows control over the
// the keep alive time, so it isn't necessarily a bad thing.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return c, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(2 * time.Minute)
	return tc, nil
}
