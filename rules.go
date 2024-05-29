package audit

import (
	botdetector "github.com/krakendio/krakend-botdetector/v2/krakend"
	cb "github.com/krakendio/krakend-circuitbreaker/v2/gobreaker"
	cors "github.com/krakendio/krakend-cors/v2"
	gelf "github.com/krakendio/krakend-gelf/v2"
	gologging "github.com/krakendio/krakend-gologging/v2"
	httpsecure "github.com/krakendio/krakend-httpsecure/v2"
	jose "github.com/krakendio/krakend-jose/v2"
	logstash "github.com/krakendio/krakend-logstash/v2"
	metrics "github.com/krakendio/krakend-metrics/v2"
	opencensus "github.com/krakendio/krakend-opencensus/v2"
	ratelimitProxy "github.com/krakendio/krakend-ratelimit/v3/proxy"
	ratelimit "github.com/krakendio/krakend-ratelimit/v3/router"
	"github.com/luraproject/lura/v2/proxy"
	router "github.com/luraproject/lura/v2/router/gin"
	server "github.com/luraproject/lura/v2/transport/http/server/plugin"
)

func hasBit(x, y int) bool {
	return (x>>y)&1 == 1
}

func hasBasicAuth(s *Service) bool {
	// check basic auth in plugin
	if len(s.Components[server.Namespace]) > 0 && hasBit(s.Components[server.Namespace][0], parseServerPlugin("basic-auth")) {
		// old plugin basic auth
		return true
	}
	if len(s.Components["auth/basic"]) > 0 && hasBit(s.Components["auth/basic"][0], 0) {
		// main server config has auth/basic enabled
		return true
	}

	for _, e := range s.Endpoints {
		if len(e.Components["auth/basic"]) > 0 && hasBit(e.Components["auth/basic"][0], 0) {
			return true
		}
	}

	return false
}

func hasApiKeys(s *Service) bool {
	_, ok := s.Components["auth/api-keys"]
	return ok
}

func hasNoJWT(s *Service) bool {
	for _, e := range s.Endpoints {
		if _, ok := e.Components[jose.ValidatorNamespace]; ok {
			return false
		}
	}
	return true
}

func hasInsecureConnections(s *Service) bool {
	return hasBit(s.Details[0], ServiceAllowInsecureConnections)
}

func hasNoTLS(s *Service) bool {
	return !hasBit(s.Details[0], ServiceHasTLS)
}

func hasTLSDisabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceHasTLS) && !hasBit(s.Details[0], ServiceTLSEnabled)
}

func hasNoHTTPSecure(s *Service) bool {
	_, ok := s.Components[httpsecure.Namespace]
	return !ok
}

func hasH2C(s *Service) bool {
	if hasBit(s.Details[0], ServiceUseH2C) {
		return true
	}
	// this is the deprecated way of assing h2c
	v, ok := s.Components[router.Namespace]
	if !ok || len(v) == 0 {
		return false
	}
	return hasBit(v[0], RouterUseH2C)
}

func hasBackendInsecureConnections(s *Service) bool {
	for _, e := range s.Endpoints {
		for _, b := range e.Backends {
			v, ok := b.Components["backend/http/client"]
			if !ok || len(v) == 0 {
				continue
			}
			if hasBit(v[0], BackendComponentHTTPClientAllowInsecureConnections) {
				return true
			}
		}
	}
	return false
}

func hasEndpointWildcard(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], BitEndpointWildcard) {
			return true
		}
	}
	return false
}

func hasEndpointCatchAll(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], BitEndpointCatchAll) {
			return true
		}
	}
	return false
}

func hasMultipleUnsafeMethods(s *Service) bool {
	for _, e := range s.Endpoints {
		if e.Details[5] > 1 {
			return true
		}
	}
	return false
}

func hasSequentialProxy(s *Service) bool {
	for _, e := range s.Endpoints {
		p, ok := e.Components[proxy.Namespace]
		if ok && len(p) > 0 && hasBit(p[0], 0) {
			return true
		}
	}
	return false
}

func hasQueryStringWildcard(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], 1) {
			return true
		}
	}
	return false
}

func hasHeadersWildcard(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], 2) {
			return true
		}
	}
	return false
}

func hasNoObfuscatedVersionHeader(s *Service) bool {
	v, ok := s.Components[router.Namespace]
	if !ok || len(v) == 0 {
		return true
	}
	return !hasBit(v[0], RouterHideVersionHeader)
}

func hasNoCORS(s *Service) bool {
	_, ok := s.Components[cors.Namespace]
	return !ok
}

func hasBotdetectorDisabled(s *Service) bool {
	_, ok := s.Components[botdetector.Namespace]
	return !ok
}

func hasNoRatelimit(s *Service) bool {
	_, ok := s.Components[ratelimit.Namespace]
	if ok {
		return false
	}
	for _, e := range s.Endpoints {
		_, ok := e.Components[ratelimit.Namespace]
		if ok {
			return false
		}
		_, ok = e.Components[ratelimitProxy.Namespace]
		if ok {
			return false
		}
		for _, b := range e.Backends {
			_, ok := b.Components[ratelimitProxy.Namespace]
			if ok {
				return false
			}
		}
	}

	_, ok = s.Components["qos/ratelimit/service"]
	if ok {
		return false
	}

	serverPlugins, ok := s.Components[server.Namespace]
	if ok && len(serverPlugins) > 0 {
		pluginsBitset := serverPlugins[0]
		redisRateLimitBit := parseServerPlugin("redis-ratelimit")
		if hasBit(pluginsBitset, redisRateLimitBit) {
			return false
		}
	}

	return true
}

func hasNoCB(s *Service) bool {
	for _, e := range s.Endpoints {
		_, ok := e.Components[cb.Namespace]
		if ok {
			return false
		}
		for _, b := range e.Backends {
			_, ok := b.Components[cb.Namespace]
			if ok {
				return false
			}
		}
	}
	return true
}

func hasTimeoutBiggerThan(d int) func(*Service) bool {
	return func(s *Service) bool {
		for _, e := range s.Endpoints {
			if e.Details[3] > d {
				return true
			}
		}
		return false
	}
}

func hasNoMetrics(s *Service) bool {
	for _, k := range []string{
		opencensus.Namespace,
		metrics.Namespace,
		"telemetry/newrelic",
		"telemetry/ganalytics",
		"telemetry/instana",
	} {
		if _, ok := s.Components[k]; ok {
			return false
		}
	}
	return true
}

func hasSeveralTelemetryComponents(s *Service) bool {
	tot := 0
	for _, k := range []string{
		opencensus.Namespace,
		metrics.Namespace,
		"telemetry/newrelic",
		"telemetry/ganalytics",
		"telemetry/instana",
	} {
		if _, ok := s.Components[k]; ok {
			tot++
		}
	}
	return tot > 1
}

func hasNoTracing(s *Service) bool {
	_, ok1 := s.Components[opencensus.Namespace]
	_, ok2 := s.Components["telemetry/newrelic"]
	_, ok3 := s.Components["telemetry/instana"]
	return !ok1 && !ok2 && !ok3
}

func hasNoLogging(s *Service) bool {
	_, ok1 := s.Components[gologging.Namespace]
	_, ok2 := s.Components[gelf.Namespace]
	_, ok3 := s.Components[logstash.Namespace]
	return !ok1 && !ok2 && !ok3
}

func hasRestfulDisabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceDisableStrictREST)
}

func hasDebugEnabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceDebug)
}

func hasEchoEnabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceEcho)
}

func hasEndpointWithoutBackends(s *Service) bool {
	for _, e := range s.Endpoints {
		if len(e.Backends) == 0 {
			return true
		}
	}
	return false
}

func hasASingleBackendPerEndpoint(s *Service) bool {
	for _, e := range s.Endpoints {
		if len(e.Backends) > 1 {
			return false
		}
	}
	return true
}

func hasAllEndpointsAsNoop(s *Service) bool {
	for _, e := range s.Endpoints {
		if !hasBit(e.Details[0], EncodingNOOP) {
			return false
		}
	}
	return true
}

func hasSequentialStart(s *Service) bool {
	return hasBit(s.Details[0], ServiceSequentialStart) && len(s.Agents) >= 10
}
