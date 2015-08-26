package main

import (
	"log"
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

func main() {
	// Don't care if this succeeds or not at this point.
	updateMirrorMappings(MappingRemoteLocation, MappingLocalLocation)

	// Setup the primary server object.
	replacers := loadMirrorMappings(MappingLocalLocation)
	myHandler := &ProxyServer{
		BufferChan: make(chan []byte, 20),
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
	myHandler.SetReplacers(replacers)

	// Setup the background mapping updater.
	go loopUpdateMirrorMappings(myHandler, MappingRemoteLocation, MappingLocalLocation, MappingUpdateInterval)

	// Create the HTTP server.
	server := http.Server{
		Addr:           ":8081",
		Handler:        myHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// GO!
	log.Fatal(server.ListenAndServe())
}
