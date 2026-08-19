package sqlstore

// SQL holds relational database configuration, used by services that
// support a relational storage backend as an alternative to MongoDB.
// Backend selection is config-time only: a running service uses exactly
// one backend for its whole lifetime.
type SQL struct {
	// Backend selects the storage backend for services that support relational
	// storage. "mongo" (default, current behavior) keeps existing Mongo-backed
	// behavior unchanged; "postgres" and "mariadb" select the corresponding
	// relational backend.
	Backend string `yaml:"backend" default:"mongo" validate:"omitempty,oneof=mongo postgres mariadb"`
	// Postgres holds Postgres-specific connection settings, used when Backend is "postgres".
	Postgres *PostgresConfig `yaml:"postgres,omitempty" validate:"required_if=Backend postgres"`
	// MariaDB holds MariaDB/MySQL-specific connection settings, used when Backend is "mariadb".
	MariaDB *MariaDBConfig `yaml:"mariadb,omitempty" validate:"required_if=Backend mariadb"`
}

// PostgresConfig holds PostgreSQL connection settings.
type PostgresConfig struct {
	// Host is the Postgres server hostname. Required when Common.SQL.Backend
	// is "postgres"; enforced by a SQL-level struct validation rather than a
	// plain "required_if" tag here, since "Backend" lives on the parent SQL
	// struct, not on PostgresConfig, and required_if can only reference
	// sibling fields.
	Host string `yaml:"host" validate:"omitempty" doc_example:"\"postgres\""`
	// Port is the Postgres server port
	Port int `yaml:"port" default:"5432"`
	// User is the Postgres connection user. Required when Common.SQL.Backend
	// is "postgres" (see Host doc comment for why this isn't a required_if tag).
	User string `yaml:"user" validate:"omitempty"`
	// Password is the Postgres connection password. May also be set via secrets.yaml
	// (Common.SQL.Postgres.Password), following the same split as Mongo.URI.
	Password string `yaml:"password,omitempty"`
	// Database is the Postgres database name
	Database string `yaml:"database" default:"vc" doc_example:"\"vc\""`
	// SSLMode is the Postgres SSL mode: disable, require, verify-ca, or verify-full
	SSLMode string `yaml:"ssl_mode" default:"disable" validate:"omitempty,oneof=disable require verify-ca verify-full"`
	// CAFilePath is the path to a PEM-encoded CA certificate used to verify the server's certificate.
	CAFilePath string `yaml:"ca_file_path,omitempty"`
	// CertFilePath is the path to a PEM-encoded client certificate for mutual TLS (mTLS).
	CertFilePath string `yaml:"cert_file_path,omitempty" validate:"required_with=KeyFilePath"`
	// KeyFilePath is the path to a PEM-encoded client private key for mutual TLS (mTLS).
	KeyFilePath string `yaml:"key_file_path,omitempty" validate:"required_with=CertFilePath"`
	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns int `yaml:"max_open_conns" default:"25"`
	// MaxIdleConns is the maximum number of idle connections in the pool.
	MaxIdleConns int `yaml:"max_idle_conns" default:"5"`
}

// MariaDBConfig holds MariaDB/MySQL connection settings.
// Kept as a separate struct from PostgresConfig (rather than shared) since
// default port and TLS parameter semantics differ enough between the two
// drivers to want independent validation tags.
type MariaDBConfig struct {
	// Host is the MariaDB server hostname. Required when Common.SQL.Backend
	// is "mariadb"; enforced by a SQL-level struct validation rather than a
	// plain "required_if" tag here, since "Backend" lives on the parent SQL
	// struct, not on MariaDBConfig, and required_if can only reference
	// sibling fields.
	Host string `yaml:"host" validate:"omitempty" doc_example:"\"mariadb\""`
	// Port is the MariaDB server port
	Port int `yaml:"port" default:"3306"`
	// User is the MariaDB connection user. Required when Common.SQL.Backend
	// is "mariadb" (see Host doc comment for why this isn't a required_if tag).
	User string `yaml:"user" validate:"omitempty"`
	// Password is the MariaDB connection password. May also be set via secrets.yaml
	// (Common.SQL.MariaDB.Password), following the same split as Mongo.URI.
	Password string `yaml:"password,omitempty"`
	// Database is the MariaDB database name
	Database string `yaml:"database" default:"vc" doc_example:"\"vc\""`
	// TLS enables TLS for the MariaDB connection.
	TLS bool `yaml:"tls" default:"false"`
	// CAFilePath is the path to a PEM-encoded CA certificate used to verify the server's certificate.
	CAFilePath string `yaml:"ca_file_path,omitempty"`
	// CertFilePath is the path to a PEM-encoded client certificate for mutual TLS (mTLS).
	CertFilePath string `yaml:"cert_file_path,omitempty" validate:"required_with=KeyFilePath"`
	// KeyFilePath is the path to a PEM-encoded client private key for mutual TLS (mTLS).
	KeyFilePath string `yaml:"key_file_path,omitempty" validate:"required_with=CertFilePath"`
	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns int `yaml:"max_open_conns" default:"25"`
	// MaxIdleConns is the maximum number of idle connections in the pool.
	MaxIdleConns int `yaml:"max_idle_conns" default:"5"`
}
