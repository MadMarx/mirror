package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"
)

type ProxyServer struct {
	Edge       string
	Origin     string
	BufferChan chan []byte
	Client     http.Client
	Replacer   *strings.Replacer
	MakeCount  *int
}

func (self ProxyServer) TakeBuffer() (b []byte) {
	select {
	case b = <-self.BufferChan:
	default:
		b = make([]byte, 2<<15)
		//b = make([]byte, 1024000)
		*(self.MakeCount)++
	}
	return
}

func (self ProxyServer) GiveBuffer(b []byte) {
	select {
	case self.BufferChan <- b:
	default:
		b = nil
	}
}

func (self ProxyServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// Clean up the request for passing on to the next server.
	request.URL.Scheme = "http"
	request.URL.Host = self.Origin
	request.RequestURI = ""
	request.Host = ""

	// Do the request to the remote server
	resp, err := self.Client.Do(request)
	if err != nil {
		fmt.Println("Things Failed.", err)
		response.WriteHeader(503)
		fmt.Fprintf(response, "503 Unable to contact upstream service.")
		return
	} else {
		for k, values := range resp.Header {
			for _, v := range values {
				if strings.Contains(v, self.Origin) {
					v = self.Replacer.Replace(v)
				}
				response.Header().Add(k, v)
			}
		}
	}
	replaceContent := strings.Contains(resp.Header.Get("Content-Type"), "text")
	gzipContent := strings.Contains(resp.Header.Get("Content-Encoding"), "gzip")
	if replaceContent {
		response.Header().Del("Content-Length")
	}

	// Flush the headers down stream.
	response.WriteHeader(resp.StatusCode)

	// some things that only need to be initialized once.
	pos, gcount := 0, 0
	var readErr error

	// These are for abstraction
	var inputStream io.Reader
	var outputStream io.Writer

	if gzipContent && replaceContent {
		// Close doesn't exist on io.Reader and ioWriter
		// so gotta create variables to get around the
		// typing of inputStream
		inputGunzipStream, _ := gzip.NewReader(resp.Body)
		outputGzipStream := gzip.NewWriter(response)
		defer inputGunzipStream.Close()
		defer outputGzipStream.Close()
		inputStream = inputGunzipStream
		outputStream = outputGzipStream
	} else {
		inputStream = resp.Body
		outputStream = response
	}

	// Deal with allocating and releasing the buffer
	buffer := self.TakeBuffer()
	defer self.GiveBuffer(buffer)

	readErr = nil
	for readErr == nil && err == nil {

		// Read from server and write to client.
		gcount, readErr = inputStream.Read(buffer[pos:])
		if gcount > 0 {
			if replaceContent {
				// Splitting a Slice shouldn't copy data,
				// atleast that is what the code looks like.
				pieces := bytes.Split(buffer[0:pos+gcount], []byte(self.Origin))
				if len(pieces) > 1 {
					for _, chunk := range pieces[:len(pieces)-1] {
						gcount, err = outputStream.Write(chunk)
						gcount, err = outputStream.Write([]byte(self.Edge))
					}
					lastChunk := pieces[len(pieces)-1]
					if readErr != nil {
						gcount, err = outputStream.Write(lastChunk)
					} else {
						pos = copy(buffer, lastChunk)
					}
				} else {
					gcount, err = outputStream.Write(buffer[:pos+gcount])
					pos = 0
				}
			} else {
				gcount, err = outputStream.Write(buffer[:gcount])
			}
		}
		if f, ok := response.(http.Flusher); ok {
			f.Flush()
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("%s,%t,%d,%d,%d,%d,%d,%d\n", request.URL, gzipContent, m.HeapSys>>10, m.HeapAlloc>>10, m.HeapIdle>>10, m.HeapReleased>>10, m.HeapObjects, *(self.MakeCount))
}

func main() {
	myHandler := ProxyServer{
		Edge:       "127.0.0.1:8081",
		Origin:     "www.reddit.com",
		BufferChan: make(chan []byte, 20),
	}

	var (
		makeCount int
	)
	myHandler.Replacer = strings.NewReplacer(myHandler.Origin, myHandler.Edge)
	myHandler.MakeCount = &makeCount
	server := http.Server{
		Addr:           myHandler.Edge,
		Handler:        myHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}
