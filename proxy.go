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
	GzipChan   chan gzipPair
	Client     http.Client
	Captcha    *CaptchaContext
}

func (self *ProxyServer) takeBuffer() (b []byte) {
	select {
	case b = <-self.BufferChan:
	default:
		b = make([]byte, ByteBufferSize)
	}
	return
}

func (self *ProxyServer) giveBuffer(b []byte) {
	select {
	case self.BufferChan <- b:
	default:
		b = nil
	}
}

type gzipPair struct {
	Reader *gzip.Reader
	Writer *gzip.Writer
}

func (self *ProxyServer) takeGzip(r io.Reader, w io.Writer) (gzp gzipPair) {
	select {
	case gzp = <-self.GzipChan:
		gzp.Reader.Reset(r)
		gzp.Writer.Reset(w)
	default:
		gzp = gzipPair{}
		gzp.Reader, _ = gzip.NewReader(r)
		gzp.Writer, _ = gzip.NewWriterLevel(w, GzipCompressionLevel)
	}
	return
}

func (self *ProxyServer) giveGzip(gzp gzipPair) {
	gzp.Reader.Close()
	gzp.Writer.Close()
	select {
	case self.GzipChan <- gzp:
	default:
		gzp.Reader = nil
		gzp.Writer = nil
	}
}

func (self *ProxyServer) GetConfiguration(edge string) (*ProxyConfig, string) {
	dnsParts := strings.Split(edge, ".")
	self.Replacers.RLock()
	defer self.Replacers.RUnlock()
	for h := 0; h < len(dnsParts); h++ {
		key := strings.Join(dnsParts[h:], ".")
		if proxyConfig, ok := self.Replacers.m[key]; ok {
			return proxyConfig, key
		}
	}
	return nil, ""
}

func (self *ProxyServer) SetConfigurations(replacers Mappings) {
	self.Replacers.Lock()
	defer self.Replacers.Unlock()
	self.Replacers.m = replacers
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
		proxyConfig  *ProxyConfig
		origin, edge string
		edgePort     string
		readErr      error
		inputStream  io.Reader
		outputStream io.Writer
	)

	// We need the proxy config to handle the inbound hostname.
	if len(request.Host) > 0 {
		hostParts := strings.Split(request.Host, ":")
		if len(hostParts) > 1 {
			edgePort = ":" + hostParts[1]
		}
		proxyConfig, edge = self.GetConfiguration(hostParts[0])

		// Some string manipulation to preserve the requested subdomains.
		// e.g. edge=foobar.com, request.Host=images.foobar.com:8080, proxyConfig.Origin=examples.com
		// images.foobar.com:8080 -> images.examples.com
		hostParts = strings.Split(request.Host, edge+edgePort)
		origin = strings.Join(hostParts, proxyConfig.Origin)
	}

	// No proxy config, no response.
	if proxyConfig == nil {
		return &ProxyError{
			Code: 501,
			Msg:  "Unable to identify requested service.",
			Err:  fmt.Errorf("Did not know the requested host: %s", request.Host),
		}
	}

	// Check to make sure we are dealing with a human before we waste any more resouces.
	if HumanCookieCheck {
		if humanCookie, err := request.Cookie(HumanCookieName); err != nil || !self.Captcha.ValidToken(humanCookie.Value) {
			return self.Captcha.Challenge(response, request, edge)
		}
	}

	// Clean up the request for passing on to the next server.
	request.URL.Scheme = "http"
	if request.TLS != nil {
		request.URL.Scheme = "https"
	}
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
			// We single out location here because the port matters for it.
			// Things like Set Cookie and others don't care about ports.
			// Depending on which way is more common, this should evolve.
			if "Location" == k {
				parts := strings.Split(v, proxyConfig.Origin)
				v = strings.Join(parts, edge+edgePort)
			} else {
				v = proxyConfig.Outbound.Replace(v)
			}
			response.Header().Add(k, v)
		}
	}
	replaceContent := strings.Contains(resp.Header.Get("Content-Type"), "text") ||
		strings.Contains(resp.Header.Get("Content-Type"), "application/javascript")
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
		gzp := self.takeGzip(resp.Body, response)
		defer self.giveGzip(gzp)
		inputStream = gzp.Reader
		outputStream = gzp.Writer
	} else {
		inputStream = resp.Body
		outputStream = response
	}

	// Buffer management
	pos, gcount := 0, 0
	buffer := self.takeBuffer()
	defer self.giveBuffer(buffer)

	readErr = nil
	for readErr == nil && err == nil {
		// Read from server and write to client.
		gcount, readErr = inputStream.Read(buffer[pos:])

		if gcount > 0 || pos+gcount > 0 {
			if replaceContent {
				// Splitting a Slice shouldn't copy data,
				pieces := bytes.Split(buffer[0:pos+gcount], []byte(proxyConfig.Origin))
				if len(pieces) > 1 {
					for _, chunk := range pieces[:len(pieces)-1] {
						gcount, err = outputStream.Write(chunk)
						gcount, err = outputStream.Write([]byte(edge))
						gcount, err = outputStream.Write([]byte(edgePort))
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
					} else if pos+gcount > len(proxyConfig.Origin) {
						remainder := buffer[pos+gcount-len(proxyConfig.Origin) : pos+gcount]
						gcount, err = outputStream.Write(buffer[:pos+gcount-len(proxyConfig.Origin)])
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
