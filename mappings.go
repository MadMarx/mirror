package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ProxyConfig struct {
	Origin      string
	OriginProto string
	Outbound    *strings.Replacer
	Certificate *tls.Certificate
}

type proxyConfigJSON struct {
	OriginProto string `json:"originproto"`
	Origin      string `json:"origin"`
	CertPEM     string `json:"cert"`
	KeyPEM      string `json:"key"`
}

type Mappings map[string]*ProxyConfig

type MappingsMutex struct {
	sync.RWMutex
	m Mappings
}

func loopUpdateMirrorMappings(server *ProxyServer, remoteLocation, localLocation string, interval time.Duration) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	for {
		// Wake up either after the interval, or when we receive sighup.
		select {
		case <-sigChan:
			break
		case <-time.After(interval):
			break
		}

		// Do the work.
		if updateMirrorMappings(remoteLocation, localLocation) {
			mappings := loadMirrorMappings(localLocation)
			server.SetConfigurations(mappings)
		}
	}
}

func loadMirrorMappings(localLocation string) (result Mappings) {
	result = make(Mappings)

	cfgFile, err := os.Open(localLocation)
	if err != nil {
		log.Printf("Unable to open the mappings file to read the config. %s", err.Error())
		return
	}

	jsonParser := json.NewDecoder(cfgFile)
	var settings = make(map[string]*proxyConfigJSON, 0)
	if err = jsonParser.Decode(&settings); err != nil {
		log.Printf("Unable to process the mappings file to read the config. %s", err.Error())
		return
	}

	// Loop over the loaded JSON structure, to convert it into the correct objects.
	// TODO move this into a property loader on the ProxyConfig object instead of
	// using a different object for temporary parsing.
	for key, val := range settings {
		result[key] = &ProxyConfig{
			Origin:      val.Origin,
			OriginProto: val.OriginProto,
			Outbound:    strings.NewReplacer(val.Origin, key),
		}
		if len(val.CertPEM) > 0 && len(val.KeyPEM) > 0 {
			if cert, err := tls.X509KeyPair([]byte(val.CertPEM), []byte(val.KeyPEM)); err != nil {
				log.Printf("%s->%s: Unable to process key pair. TLS is disabled. %s", key, val.Origin, err.Error())
			} else {
				result[key].Certificate = &cert
			}
		}
	}

	return
}

func updateMirrorMappings(remoteLocation, localLocation string) bool {
	var (
		err      error
		client   http.Client
		request  *http.Request
		response *http.Response
	)
	client.Timeout = 7 * time.Second
	if request, err = http.NewRequest("GET", remoteLocation, nil); err != nil {
		log.Printf("Unable to create the request to update the mappings file. %s", err.Error())
		return false
	}
	if response, err = client.Do(request); err != nil {
		log.Printf("Unable to perform the request to update the mappings file. %s", err.Error())
		return false
	}

	var body []byte
	if body, err = ioutil.ReadAll(response.Body); err != nil {
		log.Printf("Unable to read the data to update the mappings file. %s", err.Error())
		return false
	}

	// We marshal the results into a map to make sure the results are
	// going to load correctly at startup.
	var settings map[string]*proxyConfigJSON
	if err = json.Unmarshal(body, &settings); err != nil {
		log.Printf("Unable to parse the data to update the mappings file. %s", err.Error())
		return false
	}

	tempNameBuf := make([]byte, 18)
	if _, err = rand.Read(tempNameBuf); err != nil {
		log.Printf("Unable to calculate the tempfile name to write the mappings. %s", err.Error())
		return false
	}

	tempPath := localLocation + ".tmp" + base64.URLEncoding.EncodeToString(tempNameBuf)

	var tempFile *os.File
	if tempFile, err = os.Create(tempPath); err != nil {
		log.Printf("Unable to create the tempfile to write the mappings. %s", err.Error())
		return false
	}

	jsonParser := json.NewEncoder(tempFile)
	if err = jsonParser.Encode(&settings); err != nil {
		log.Printf("Unable to write the tempfile mappings as json. %s", err.Error())
		return false
	}

	if err = tempFile.Close(); err != nil {
		log.Printf("Unable to close the tempfile for the mappings. %s", err.Error())
		return false
	}

	if err = os.Rename(tempPath, localLocation); err != nil {
		log.Printf("Unable to the mappings from tempfile to real file. %s", err.Error())
		return false
	}

	log.Printf("Updated the mirrors config.")
	return true
}
