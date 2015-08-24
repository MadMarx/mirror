package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type NoRedirectError struct{}

func (e *NoRedirectError) Error() string {
	return "This server doesn't follow redirects."
}

var nre NoRedirectError

func noClientRedirect(r *http.Request, via []*http.Request) error {
	return &nre
}

type ProxyError struct {
	Code int
	Msg  string
	Err  error
}

type ProxyServer struct {
	Replacers  MappingsMutex
	BufferChan chan []byte
	Client     http.Client
	Captcha    *CaptchaContext
}

func (self *ProxyServer) TakeBuffer() (b []byte) {
	select {
	case b = <-self.BufferChan:
	default:
		b = make([]byte, 2<<15)
	}
	return
}

func (self *ProxyServer) GiveBuffer(b []byte) {
	select {
	case self.BufferChan <- b:
	default:
		b = nil
	}
}

func (self *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if result := self.ProcessRequest(w, r); result != nil {
		w.WriteHeader(result.Code)
		fmt.Fprintf(w, "%d: %s.", result.Code, result.Msg)
		if result.Err != nil {
			log.Printf("Error|%v|%d|%s|%s|%v", start, result.Code, r.URL, result.Msg, result.Err)
		}
	}
	end := time.Now()
	log.Printf("Time|%s|%v|%v", r.URL, end, end.Sub(start))
}

func (self *ProxyServer) ProcessRequest(response http.ResponseWriter, request *http.Request) *ProxyError {

	var (
		replacer     *ReplacerPair
		origin, edge string
		readErr      error
		inputStream  io.Reader
		outputStream io.Writer
	)

	// We need the replacer to handle the inbound hostname.
	if request.Host != "" {
		// First, check to see if the request had the host header set.
		replacer, edge = self.GetReplacer(request.Host)
	}
	if replacer == nil {
		return &ProxyError{
			Code: 501,
			Msg:  "Unable to identify requested service.",
			Err:  fmt.Errorf("Did not know the requested host: %s", request.Host),
		}
	}
	origin = replacer.inbound.Replace(request.Host)

	// Check to make sure we are dealing with a human before we waste any more resouces.
	if HumanCookieCheck {
		if humanCookie, err := request.Cookie(HumanCookieName); err != nil || !self.Captcha.ValidToken(humanCookie.Value) {
			return self.Captcha.Challenge(response, request, edge)
		}
	}

	// Clean up the request for passing on to the next server.
	request.URL.Scheme = "http"
	request.URL.Host = origin
	request.RequestURI = ""
	request.Host = ""

	// Do the request to the remote server
	resp, err := self.Client.Do(request)
	if err != nil {
		// Unwind the redirect prevention.
		if urlErr, ok := err.(*url.Error); ok {
			if _, ok = urlErr.Err.(*NoRedirectError); ok {
				err = nil
			}
		}
		if err != nil {
			return &ProxyError{
				Code: 502,
				Msg:  "Unable to contact upstream service.",
				Err:  err,
			}
		}
	}

	// Process the Headers.
	for k, values := range resp.Header {
		for _, v := range values {
			v = replacer.outbound.Replace(v)
			response.Header().Add(k, v)
		}
	}
	replaceContent := strings.Contains(resp.Header.Get("Content-Type"), "text")
	gzipContent := strings.Contains(resp.Header.Get("Content-Encoding"), "gzip")

	if replaceContent {
		response.Header().Del("Content-Length")
	}

	// Flush the headers down stream.
	// NOTE: This means errors after here are going to look like truncated content.
	response.WriteHeader(resp.StatusCode)

	if gzipContent && replaceContent {
		// Close doesn't exist on io.Reader and io.Writer
		// so using the specific types to register the defer.
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

	// Buffer management
	pos, gcount := 0, 0
	buffer := self.TakeBuffer()
	defer self.GiveBuffer(buffer)

	readErr = nil
	for readErr == nil && err == nil {
		// Read from server and write to client.
		gcount, readErr = inputStream.Read(buffer[pos:])

		if gcount > 0 || pos+gcount > 0 {
			if replaceContent {
				// Splitting a Slice shouldn't copy data,
				pieces := bytes.Split(buffer[0:pos+gcount], []byte(origin))
				if len(pieces) > 1 {
					for _, chunk := range pieces[:len(pieces)-1] {
						gcount, err = outputStream.Write(chunk)
						gcount, err = outputStream.Write([]byte(edge))
					}
					lastChunk := pieces[len(pieces)-1]
					if readErr != nil {
						gcount, err = outputStream.Write(lastChunk)
					} else {
						pos = copy(buffer, lastChunk)
					}
				} else {
					if readErr != nil {
						gcount, err = outputStream.Write(buffer[:pos+gcount])
						pos = 0
					} else if pos+gcount > len(origin) {
						remainder := buffer[pos+gcount-len(origin) : pos+gcount]
						gcount, err = outputStream.Write(buffer[:pos+gcount-len(origin)])
						pos = copy(buffer, remainder)
					} else {
						pos += gcount
					}
				}
			} else {
				gcount, err = outputStream.Write(buffer[:gcount])
			}
		}
		if f, ok := response.(http.Flusher); ok {
			f.Flush()
		}
	}
	return nil
}

func (self *ProxyServer) GetReplacer(edge string) (*ReplacerPair, string) {
	dnsParts := strings.Split(edge, ".")
	self.Replacers.RLock()
	defer self.Replacers.RUnlock()
	for h := 0; h < len(dnsParts); h++ {
		key := strings.Join(dnsParts[h:], ".")
		if replacer, ok := self.Replacers.m[key]; ok {
			return replacer, key
		}
	}
	return nil, ""
}

func (self *ProxyServer) SetReplacers(replacers Mappings) {
	self.Replacers.Lock()
	defer self.Replacers.Unlock()
	self.Replacers.m = replacers
}
