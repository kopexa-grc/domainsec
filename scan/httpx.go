package scan

import (
	"context"

	"github.com/kopexa-grc/domainsec/inventory"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

func onResult(r runner.Result, hosts []*inventory.HostEntry) {
	// Find the corresponding host entry
	for _, host := range hosts {
		if host.Host == r.Input {
			if r.Err != nil || r.Error != "" || r.Failed {
				if r.Err != nil {
					host.Err = r.Err.Error()
				} else {
					host.Err = r.Error
				}
			}

			host.StatusCode = int32(r.StatusCode)
			host.ContentType = r.ContentType
			host.CdnName = r.CDNName
			host.CdnType = r.CDNType
			host.Webserver = r.WebServer
			host.Technologies = r.Technologies
			host.Sni = r.SNI
			host.Title = r.Title
			host.Scheme = r.Scheme
			host.ARecords = r.A
			host.AaaaRecords = r.AAAA
			host.Cdn = r.CDN
			host.ScreenshotBytes = r.ScreenshotBytes
			host.Cnames = r.CNAMEs

			if len(r.TechnologyDetails) > 0 {
				if host.TechnologyDetails == nil {
					host.TechnologyDetails = make(map[string]*inventory.TechnologyDetail, len(r.TechnologyDetails))
				}

				for name, app := range r.TechnologyDetails {
					host.TechnologyDetails[name] = &inventory.TechnologyDetail{
						Description: app.Description,
						Website:     app.Website,
						Cpe:         app.CPE,
						Icon:        app.Icon,
						Categories:  app.Categories,
					}
				}
			}

			// Redirects / Final URL
			if r.FinalURL != "" {
				host.FinalUrl = r.FinalURL
			} else if r.URL != "" {
				host.FinalUrl = r.URL
			}

			// redirect_hops: bevorzugt ChainStatusCodes, sonst Chain-Länge
			if n := len(r.ChainStatusCodes); n > 0 {
				host.RedirectHops = int32(n)
			} else if n := len(r.Chain); n > 0 {
				host.RedirectHops = int32(n)
			}

			// HTTP Security Headers
			if h := mapHTTPHeadersFromIface(r.ResponseHeaders); h != nil {
				host.HttpHeaders = h
			}

			// Posture-heuristics
			body := r.ResponseBody
			// fallback: headless body, if set
			if body == "" && r.HeadlessBody != "" {
				body = r.HeadlessBody
			}

			host.LoginFormDetected = detectLoginForm(body)
			host.CookiesOverHttp = detectCookiesOverHTTP(r.ResponseHeaders, r.Scheme)
			host.MixedContentDetected = detectMixedContent(body, r.Scheme)

			host.TlsInfo = extractTLSInfo(context.Background(), r)

			break
		}
	}
}

func (s *Scanner) probehosts(_ctx context.Context, hosts []*inventory.HostEntry) error {
	rawHosts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		rawHosts = append(rawHosts, host.Host)
	}

	// run httpx
	options := runner.Options{
		DisableStdin:    true, // Running as a server, no stdin
		Silent:          true,
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice(rawHosts),
		OnResult: func(r runner.Result) {
			onResult(r, hosts)
		},
		FollowRedirects: true,
		MaxRedirects:    5,
		Timeout:         10,
		TechDetect:      true,
		ExtractTitle:    true,
		TLSGrab:         true,
		Probe:           true,
		RandomAgent:     true,
	}

	if err := options.ValidateOptions(); err != nil {
		return err
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return err
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	return nil
}
