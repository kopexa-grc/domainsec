// Copyright (c) Kopexa GmbH
// SPDX-License-Identifier: BUSL-1.1

package scan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/kopexa-grc/domainsec/inventory"
	"github.com/projectdiscovery/httpx/runner"
)

// Header aus map[string]interface{} case-insensitive holen
func getHeaderFromIface(h map[string]interface{}, key string) string {
	if h == nil {
		return ""
	}
	lkey := strings.ToLower(key)
	for k, v := range h {
		if strings.ToLower(k) != lkey {
			continue
		}
		switch t := v.(type) {
		case string:
			return t
		case []string:
			if len(t) > 0 {
				return strings.Join(t, ", ")
			}
		case []interface{}:
			parts := make([]string, 0, len(t))
			for _, iv := range t {
				if s, ok := iv.(string); ok {
					parts = append(parts, s)
				}
			}
			return strings.Join(parts, ", ")
		default:
			// best-effort
			return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(any(v).(interface{}).(string)), "\n", " "), "\r", " "))
		}
	}
	return ""
}

func mapHTTPHeadersFromIface(h map[string]interface{}) *inventory.HTTPHeaders {
	if h == nil {
		return nil
	}
	return &inventory.HTTPHeaders{
		ContentSecurityPolicy:   getHeaderFromIface(h, "Content-Security-Policy"),
		StrictTransportSecurity: getHeaderFromIface(h, "Strict-Transport-Security"),
		XContentTypeOptions:     getHeaderFromIface(h, "X-Content-Type-Options"),
		XFrameOptions:           getHeaderFromIface(h, "X-Frame-Options"),
		ReferrerPolicy:          getHeaderFromIface(h, "Referrer-Policy"),
		PermissionsPolicy:       getHeaderFromIface(h, "Permissions-Policy"),
		CrossOriginOpenerPolicy: getHeaderFromIface(h, "Cross-Origin-Opener-Policy"),
	}
}

// Heuristik: Login-Formular
func detectLoginForm(body string) bool {
	if body == "" {
		return false
	}
	b := strings.ToLower(body)
	return strings.Contains(b, "<input") &&
		(strings.Contains(b, "type=\"password\"") || strings.Contains(b, "type='password'"))
}

// Heuristik: Cookies over HTTP
func detectCookiesOverHTTP(headers map[string]interface{}, scheme string) bool {
	val := getHeaderFromIface(headers, "Set-Cookie")
	if val == "" {
		return false
	}
	// http → jeder Cookie ist „over http“
	if !strings.EqualFold(scheme, "https") {
		return true
	}
	// https → prüfe Secure-Flag
	lv := strings.ToLower(val)
	return !strings.Contains(lv, "secure")
}

// Heuristik: Mixed Content (nur wenn https)
func detectMixedContent(body string, scheme string) bool {
	if !strings.EqualFold(scheme, "https") || body == "" {
		return false
	}
	b := strings.ToLower(body)
	return strings.Contains(b, "src=\"http://") ||
		strings.Contains(b, "href=\"http://")
}

func extractTLSInfo(ctx context.Context, r runner.Result) *inventory.TLSInfo {
	if !strings.EqualFold(r.Scheme, "https") && r.TLSData == nil && !r.HTTP2 {
		return &inventory.TLSInfo{Detected: false}
	}

	if r.TLSData != nil {
		if ti := extractFromClientsResponse(r.TLSData); ti != nil {
			ti.Detected = true
			// ALPN: http2-Flag aus result berücksichtigen
			if r.HTTP2 && ti.Alpn == "" {
				ti.Alpn = "h2"
			}
			return ti
		}
	}

	host, port := hostPortForTLS(r)
	if host == "" {
		return &inventory.TLSInfo{Detected: true} // wir wissen, dass TLS „irgendwie“ aktiv war
	}
	if ti := activeTLSDial(ctx, host, port); ti != nil {
		ti.Detected = true
		// http2 Flag übernehmen
		if r.HTTP2 && ti.Alpn == "" {
			ti.Alpn = "h2"
		}
		return ti
	}

	return &inventory.TLSInfo{Detected: true}
}

// versucht, die Felder aus clients.Response via Reflection zu lesen.
// Wir suchen gängige Namen: TLSVersion/Version, Cipher/CipherSuite, ALPN/NegotiatedProtocol,
// Certificate/PeerCertificates mit x509.Certificate (Issuer, Subject, DNSNames, NotBefore/After).
func extractFromClientsResponse(tlsResp any) *inventory.TLSInfo {
	v := reflect.ValueOf(tlsResp)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}

	ti := &inventory.TLSInfo{}

	// Version
	if s := tryGetStringField(v, "TLSVersion", "Version"); s != "" {
		ti.Version = s
	}
	// Cipher
	if s := tryGetStringField(v, "Cipher", "CipherSuite"); s != "" {
		ti.Cipher = s
	}
	// ALPN
	if s := tryGetStringField(v, "ALPN", "NegotiatedProtocol"); s != "" {
		ti.Alpn = s
	}
	// Direkte Felder für Cert-Infos
	ti.CertIssuer = tryGetStringField(v, "CertificateIssuer", "CertIssuer", "Issuer")
	ti.CertSubject = tryGetStringField(v, "CertificateSubject", "CertSubject", "Subject")
	ti.CertSha256 = tryGetStringField(v, "CertificateSHA256", "CertSHA256", "SHA256")

	// NotBefore/NotAfter (als time.Time oder string)
	if nb := tryGetTimeOrStringField(v, "NotBefore", "CertificateNotBefore"); nb != "" {
		ti.NotBefore = nb
	}
	if na := tryGetTimeOrStringField(v, "NotAfter", "CertificateNotAfter"); na != "" {
		ti.NotAfter = na
	}
	// SANs direkt?
	if sans := tryGetStringSliceField(v, "SANs", "DNSNames"); len(sans) > 0 {
		ti.Sans = sans
	}

	// Versuche, tls.ConnectionState zu finden (Felder: "TLSConnectionState", "ConnectionState", "State")
	if cs, ok := tryGetTLSConnectionState(v, "TLSConnectionState", "ConnectionState", "State"); ok {
		fillFromConnState(ti, cs)
	}

	// Oder PeerCertificates []x509.Certificate
	if cert := tryGetFirstX509Cert(v, "PeerCertificates", "Certificates", "Certificate"); cert != nil {
		fillFromX509Cert(ti, cert)
	}

	// Falls gar keine nützlichen Infos gefunden wurden, gib nil zurück
	if ti.Version == "" && ti.Cipher == "" && ti.CertIssuer == "" && ti.CertSubject == "" && ti.CertSha256 == "" && ti.NotBefore == "" && ti.NotAfter == "" && len(ti.Sans) == 0 && ti.Alpn == "" {
		return nil
	}
	return ti
}

func tryGetStringField(v reflect.Value, names ...string) string {
	for _, name := range names {
		f := v.FieldByName(name)
		if f.IsValid() && f.CanInterface() {
			if s, ok := f.Interface().(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func tryGetTimeOrStringField(v reflect.Value, names ...string) string {
	for _, name := range names {
		f := v.FieldByName(name)
		if !f.IsValid() || !f.CanInterface() {
			continue
		}
		switch x := f.Interface().(type) {
		case time.Time:
			if !x.IsZero() {
				return x.UTC().Format(time.RFC3339)
			}
		case string:
			if x != "" {
				return x
			}
		}
	}
	return ""
}

func tryGetStringSliceField(v reflect.Value, names ...string) []string {
	for _, name := range names {
		f := v.FieldByName(name)
		if f.IsValid() && f.CanInterface() {
			switch x := f.Interface().(type) {
			case []string:
				if len(x) > 0 {
					return x
				}
			}
		}
	}
	return nil
}

func tryGetTLSConnectionState(v reflect.Value, names ...string) (tls.ConnectionState, bool) {
	for _, name := range names {
		f := v.FieldByName(name)
		if f.IsValid() && f.CanInterface() {
			if cs, ok := f.Interface().(tls.ConnectionState); ok {
				return cs, true
			}
			// *tls.ConnectionState?
			if pcs, ok := f.Interface().(*tls.ConnectionState); ok && pcs != nil {
				return *pcs, true
			}
		}
	}
	return tls.ConnectionState{}, false
}

func tryGetFirstX509Cert(v reflect.Value, names ...string) *x509.Certificate {
	for _, name := range names {
		f := v.FieldByName(name)
		if !f.IsValid() || !f.CanInterface() {
			continue
		}
		switch x := f.Interface().(type) {
		case []*x509.Certificate:
			if len(x) > 0 && x[0] != nil {
				return x[0]
			}
		case []x509.Certificate:
			if len(x) > 0 {
				return &x[0]
			}
		}
	}
	return nil
}

func fillFromConnState(ti *inventory.TLSInfo, cs tls.ConnectionState) {
	if ti.Version == "" {
		ti.Version = tlsVersionString(cs.Version)
	}
	if ti.Cipher == "" {
		ti.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	}
	if ti.Alpn == "" && cs.NegotiatedProtocol != "" {
		ti.Alpn = cs.NegotiatedProtocol
	}
	if len(cs.PeerCertificates) > 0 {
		fillFromX509Cert(ti, cs.PeerCertificates[0])
	}
}

func fillFromX509Cert(ti *inventory.TLSInfo, c *x509.Certificate) {
	if c == nil {
		return
	}
	if ti.CertIssuer == "" {
		ti.CertIssuer = c.Issuer.String()
	}
	if ti.CertSubject == "" {
		ti.CertSubject = c.Subject.String()
	}
	if ti.NotBefore == "" {
		ti.NotBefore = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if ti.NotAfter == "" {
		ti.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	if len(ti.Sans) == 0 && len(c.DNSNames) > 0 {
		ti.Sans = append(ti.Sans, c.DNSNames...)
	}
	if ti.CertSha256 == "" {
		sum := sha256.Sum256(c.Raw)
		ti.CertSha256 = hex.EncodeToString(sum[:])
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return ""
	}
}

// host:port für aktiven TLS-Handshake bestimmen
func hostPortForTLS(r runner.Result) (host string, port string) {
	// bevorzugt FinalURL
	if r.FinalURL != "" {
		if u, err := url.Parse(r.FinalURL); err == nil {
			host = u.Hostname()
			if p := u.Port(); p != "" {
				port = p
			}
		}
	}
	if host == "" && r.URL != "" {
		if u, err := url.Parse(r.URL); err == nil {
			host = u.Hostname()
			if p := u.Port(); p != "" {
				port = p
			}
		}
	}
	if host == "" {
		// fallback: r.Host (httpx setzt das oft)
		host = r.Host
	}
	if port == "" {
		// scheme-basiert
		if strings.EqualFold(r.Scheme, "https") {
			port = "443"
		} else {
			port = "443" // wir wollen TLS prüfen → 443 default
		}
	}
	return host, port
}

func activeTLSDial(ctx context.Context, host, port string) *inventory.TLSInfo {
	if host == "" || port == "" {
		return nil
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // wir wollen nur Infos sammeln, nicht validieren
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	ti := &inventory.TLSInfo{
		Version: tlsVersionString(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
		Alpn:    state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		fillFromX509Cert(ti, state.PeerCertificates[0])
	}
	return ti
}
