package sqlstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// libpqQuote quotes a libpq keyword/value connection string value if it
// contains characters that would otherwise make the value ambiguous
// (whitespace, a single quote, or a backslash), single-quoting it and
// backslash-escaping any embedded backslashes/quotes per libpq's own
// connection-string escaping rules. Values with none of those characters are
// returned unquoted, matching the plain "key=value" form used before this
// existed.
func libpqQuote(v string) string {
	if v == "" || !strings.ContainsAny(v, " '\\") {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return "'" + v + "'"
}

// DSN returns a libpq keyword/value connection string for this Postgres
// configuration, understood directly by pgx (both sslmode and the
// sslrootcert/sslcert/sslkey file-path parameters are native libpq
// connection parameters, so no separate *tls.Config needs to be built here).
func (p *PostgresConfig) DSN() string {
	parts := []string{
		"host=" + libpqQuote(p.Host),
		"port=" + strconv.Itoa(p.Port),
		"user=" + libpqQuote(p.User),
		"dbname=" + libpqQuote(p.Database),
		"sslmode=" + libpqQuote(p.SSLMode),
	}
	if p.Password != "" {
		parts = append(parts, "password="+libpqQuote(p.Password))
	}
	if p.CAFilePath != "" {
		parts = append(parts, "sslrootcert="+libpqQuote(p.CAFilePath))
	}
	if p.CertFilePath != "" {
		parts = append(parts, "sslcert="+libpqQuote(p.CertFilePath))
	}
	if p.KeyFilePath != "" {
		parts = append(parts, "sslkey="+libpqQuote(p.KeyFilePath))
	}
	return strings.Join(parts, " ")
}

// tlsConfigName is the name registered with mysql.RegisterTLSConfig for a
// given MariaDBConfig's custom TLS settings (CA/client certificate). Derived
// from Host and Port so it's stable across calls; two MariaDBConfig values
// that share the same host:port (which would also mean connecting to the
// same server) share the same registered name.
func (m *MariaDBConfig) tlsConfigName() string {
	return "vc-" + m.Host + "-" + strconv.Itoa(m.Port)
}

// DSN returns a go-sql-driver/mysql connection string for this MariaDB
// configuration. When CA/client certificate paths are set, this also
// registers a named TLS config with the mysql driver (mysql.RegisterTLSConfig)
// and references it in the returned DSN; the caller does not need to
// register anything itself.
func (m *MariaDBConfig) DSN() (string, error) {
	cfg := mysql.NewConfig()
	cfg.User = m.User
	cfg.Passwd = m.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", m.Host, m.Port)
	cfg.DBName = m.Database
	// Schema migration files contain more than one statement per file
	// (e.g. CREATE TABLE followed by CREATE INDEX); this is required for
	// the migration driver to execute all of them. Harmless for ordinary
	// single-statement queries.
	cfg.MultiStatements = true
	// Without this, DATE/DATETIME/TIMESTAMP columns are returned as raw
	// []byte instead of time.Time, breaking any row struct field typed
	// time.Time.
	cfg.ParseTime = true

	switch {
	case m.CAFilePath != "" || m.CertFilePath != "" || m.KeyFilePath != "":
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if m.CAFilePath != "" {
			caCert, err := os.ReadFile(m.CAFilePath)
			if err != nil {
				return "", fmt.Errorf("mariadb: failed to read CA file %q: %w", m.CAFilePath, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return "", fmt.Errorf("mariadb: CA file %q contains no valid PEM certificates", m.CAFilePath)
			}
			tlsCfg.RootCAs = pool
		}
		if m.CertFilePath != "" && m.KeyFilePath != "" {
			cert, err := tls.LoadX509KeyPair(m.CertFilePath, m.KeyFilePath)
			if err != nil {
				return "", fmt.Errorf("mariadb: failed to load client certificate/key (%q, %q): %w", m.CertFilePath, m.KeyFilePath, err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		name := m.tlsConfigName()
		if err := mysql.RegisterTLSConfig(name, tlsCfg); err != nil {
			return "", fmt.Errorf("mariadb: failed to register TLS config: %w", err)
		}
		cfg.TLSConfig = name
	case m.TLS:
		cfg.TLSConfig = "true"
	}

	return cfg.FormatDSN(), nil
}
