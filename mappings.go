package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type ReplacerPair struct {
	inbound  *strings.Replacer
	outbound *strings.Replacer
}

type Mappings map[string]*ReplacerPair

type MappingsMutex struct {
	sync.RWMutex
	m Mappings
}

func loopUpdateMirrorMappings(server *ProxyServer, remoteLocation, localLocation string, interval time.Duration) {
	for {
		time.Sleep(interval)
		if updateMirrorMappings(remoteLocation, localLocation) {
			mappings := loadMirrorMappings(localLocation)
			server.SetReplacers(mappings)
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
	var settings = make(map[string]string, 0)
	if err = jsonParser.Decode(&settings); err != nil {
		log.Printf("Unable to process the mappings file to read the config. %s", err.Error())
		return
	}

	for key, val := range settings {
		result[key] = &ReplacerPair{
			inbound:  strings.NewReplacer(key, val),
			outbound: strings.NewReplacer(val, key),
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
	var settings map[string]string
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

	log.Printf("TempPath= %s", tempPath)
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
