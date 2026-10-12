package tokenstatuslist

// The status-list implementations an entry can come from.
//
// These names are recorded alongside every allocated entry and travel with
// it from issuance to revocation. They live here, rather than in whichever
// service happened to need them first, because three do: the issuer
// allocates and later updates entries, the apigw records and looks them up,
// and the database layer stores the value. A second spelling of "registry"
// in any of those would route a revocation to the wrong backend, which does
// not fail - it writes a status into the wrong list.
const (
	// BackendRegistry is vc's own built-in Token Status List, served by the
	// registry service and addressed by (section, index).
	BackendRegistry = "registry"
	// BackendStatusService is an external draft-ietf-oauth-status-list
	// service, addressed by (list URI, index); it has no sections.
	BackendStatusService = "status_service"
)

// ValidBackend reports whether name is a backend this build knows how to
// reach. Anything else must be refused rather than routed somewhere.
func ValidBackend(name string) bool {
	return name == BackendRegistry || name == BackendStatusService
}
