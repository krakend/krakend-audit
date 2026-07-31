package audit

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"io"

	bf "github.com/krakend/bloomfilter/v3/krakend"
	botdetector "github.com/krakend/krakend-botdetector/v3/krakend"
	gelf "github.com/krakend/krakend-gelf/v3"
	gologging "github.com/krakend/krakend-gologging/v3"
	httpcache "github.com/krakend/krakend-httpcache/v3"
	httpsecure "github.com/krakend/krakend-httpsecure/v3"
	jose "github.com/krakend/krakend-jose/v3"
	logstash "github.com/krakend/krakend-logstash/v3"
	luaproxy "github.com/krakend/krakend-lua/v3/proxy"
	luarouter "github.com/krakend/krakend-lua/v3/router"
	ratelimitProxy "github.com/krakend/krakend-ratelimit/v4/proxy"
	ratelimit "github.com/krakend/krakend-ratelimit/v4/router"
	"github.com/luraproject/lura/v3/proxy"
	"github.com/luraproject/lura/v3/proxy/plugin"
	router "github.com/luraproject/lura/v3/router/gin"
	client "github.com/luraproject/lura/v3/transport/http/client/plugin"
	server "github.com/luraproject/lura/v3/transport/http/server/plugin"
)

// Marshal returns the encoded and compressed representation of the Service
func Marshal(s *Service) ([]byte, error) {
	content := applyAlias(s.Clone())

	buff := bytes.Buffer{}
	gzipWriter, _ := gzip.NewWriterLevel(&buff, gzip.BestCompression)
	enc := gob.NewEncoder(gzipWriter)
	if err := enc.Encode(content); err != nil {
		return buff.Bytes(), err
	}
	if err := gzipWriter.Close(); err != nil && err != io.ErrClosedPipe {
		return buff.Bytes(), err
	}
	return buff.Bytes(), nil
}

// Unmarshal decompresses and decodes the received bits into a Service
func Unmarshal(b []byte, s *Service) error {
	zr, err := gzip.NewReader(bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(zr)
	if err := dec.Decode(s); err != nil {
		return err
	}
	s.normalize()
	return nil
}

var componentAlias = map[string]string{
	server.Namespace:      "a",
	client.Namespace:      "b",
	plugin.Namespace:      "c",
	proxy.Namespace:       "d",
	router.Namespace:      "e",
	bf.Namespace:          "f",
	botdetector.Namespace: "g",
	"github_com/devopsfaith/krakend-opencensus": "h",
	ratelimit.Namespace:                         "i",
	ratelimitProxy.Namespace:                    "j",
	"telemetry/newrelic":                        "k",
	"telemetry/ganalytics":                      "l",
	"telemetry/instana":                         "m",
	jose.ValidatorNamespace:                     "n",
	jose.SignerNamespace:                        "o",
	"auth/api-keys":                             "p",
	httpsecure.Namespace:                        "q",
	gologging.Namespace:                         "r",
	gelf.Namespace:                              "s",
	logstash.Namespace:                          "t",
	"backend/grpc":                              "u",
	"auth/basic":                                "v",
	"server/virtualhost":                        "w",
	"server/static-filesystem":                  "x",
	"backend/static-filesystem":                 "y",
	"backend/http/client":                       "z",
	"telemetry/moesif":                          "0",
	"telemetry/opentelemetry":                   "1",
	"grpc":                                      "2",
	"modifier/response-body-generator":          "3",
	"validation/response-json-schema":           "4",
	"websocket":                                 "5",
	"modifier/response-headers":                 "6",
	luaproxy.ProxyNamespace:                     "7",
	luaproxy.BackendNamespace:                   "8",
	luarouter.Namespace:                         "9",
	httpcache.Namespace:                         "10",
	"ai/llm":                                    "11",
	"ai/mcp":                                    "12",
}

func applyAlias(s Service) Service {
	for k, v := range s.Components {
		if alias, ok := componentAlias[k]; ok {
			s.Components[alias] = v
			delete(s.Components, k)
		}
	}

	for i, a := range s.Agents {
		for k, v := range a.Components {
			if alias, ok := componentAlias[k]; ok {
				s.Agents[i].Components[alias] = v
				delete(s.Agents[i].Components, k)
			}
		}
		for j, b := range a.Backends {
			for k, v := range b.Components {
				if alias, ok := componentAlias[k]; ok {
					s.Agents[i].Backends[j].Components[alias] = v
					delete(s.Agents[i].Backends[j].Components, k)
				}
			}
		}
	}

	for i, e := range s.Endpoints {
		for k, v := range e.Components {
			if alias, ok := componentAlias[k]; ok {
				s.Endpoints[i].Components[alias] = v
				delete(s.Endpoints[i].Components, k)
			}
		}
		for j, b := range e.Backends {
			for k, v := range b.Components {
				if alias, ok := componentAlias[k]; ok {
					s.Endpoints[i].Backends[j].Components[alias] = v
					delete(s.Endpoints[i].Backends[j].Components, k)
				}
			}
		}
	}

	return s
}

func (s *Service) normalize() { // skipcq: GO-R1005, GO-W1029
	if s == nil {
		return
	}

	alias := map[string]string{}
	for k, v := range componentAlias {
		alias[v] = k
	}

	if s.Endpoints == nil {
		s.Endpoints = []Endpoint{}
	}
	if s.Agents == nil {
		s.Agents = []Agent{}
	}
	if s.Components == nil {
		s.Components = Component{}
	}

	for k, v := range s.Components {
		if v == nil {
			s.Components[k] = []int{}
		}
		if name, ok := alias[k]; ok {
			s.Components[name] = s.Components[k]
			delete(s.Components, k)
		}
	}

	for _, e := range s.Endpoints {
		if e.Backends == nil {
			e.Backends = []Backend{}
		}
		if e.Components == nil {
			e.Components = Component{}
		}

		for k, v := range e.Components {
			if v == nil {
				e.Components[k] = []int{}
			}
			if name, ok := alias[k]; ok {
				e.Components[name] = e.Components[k]
				delete(e.Components, k)
			}
		}

		for _, b := range e.Backends {
			if b.Components == nil {
				b.Components = Component{}
			}

			for k, v := range b.Components {
				if v == nil {
					b.Components[k] = []int{}
				}
				if name, ok := alias[k]; ok {
					b.Components[name] = b.Components[k]
					delete(b.Components, k)
				}
			}
		}
	}

	for _, a := range s.Agents {
		if a.Backends == nil {
			a.Backends = []Backend{}
		}
		if a.Components == nil {
			a.Components = Component{}
		}

		for k, v := range a.Components {
			if v == nil {
				a.Components[k] = []int{}
			}
			if name, ok := alias[k]; ok {
				a.Components[name] = a.Components[k]
				delete(a.Components, k)
			}
		}

		for _, b := range a.Backends {
			if b.Components == nil {
				b.Components = Component{}
			}

			for k, v := range b.Components {
				if v == nil {
					b.Components[k] = []int{}
				}
				if name, ok := alias[k]; ok {
					b.Components[name] = b.Components[k]
					delete(b.Components, k)
				}
			}
		}
	}
}
