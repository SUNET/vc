package pki

import (
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// A PKCS#11 module is initialized once per process, not once per user of it.
//
// C_Initialize and C_Finalize are library-wide, and pkcs11.New(path) dlopens
// a path the loader has already refcounted - so a second New of the same
// module is the same library instance, and a second Initialize of it returns
// CKR_CRYPTOKI_ALREADY_INITIALIZED. Measured, not assumed: see
// TestPKCS11Module_SharedAcrossUsers, which fails on the unshared code.
//
// That is not a theoretical collision. A deployment with two credential
// encryption keys on one token for rotation, or with an HSM-backed
// apigw.key_config alongside an HSM-backed credential encryption key, hits
// it at startup. And the inverse is worse: C_Finalize is library-wide too,
// so a caller that finalized when it was done - which
// PKCS11PrivateKey.Sign did after every single signature - pulled the
// module out from under every other session in the process.
//
// So the module lifecycle lives here, refcounted and keyed by path, and
// every user in this package goes through it. Users hold their own
// sessions; a session is the per-user object, the module is not.
var modules = struct {
	mu     sync.Mutex
	byPath map[string]*pkcs11Module
}{byPath: map[string]*pkcs11Module{}}

// pkcs11Module is one initialized module, shared by everything in this
// process that opened the same path.
type pkcs11Module struct {
	ctx  *pkcs11.Ctx
	path string
	refs int
}

// acquireModule returns the initialized module at path, initializing it on
// the first acquisition. Every successful call must be paired with
// releaseModule.
func acquireModule(path string) (*pkcs11Module, error) {
	modules.mu.Lock()
	defer modules.mu.Unlock()

	if m, ok := modules.byPath[path]; ok {
		m.refs++
		return m, nil
	}

	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", path)
	}

	if err := ctx.Initialize(); err != nil {
		// CKR_CRYPTOKI_ALREADY_INITIALIZED means something outside this
		// registry - another library in the process, or a caller of this
		// package from before it existed - has the module open. The library
		// is usable; it is the second C_Initialize that is not allowed. Take
		// it, but never finalize it, because whoever did initialize it owns
		// that call.
		var code pkcs11.Error
		if !errors.As(err, &code) || code != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
		}
		// foreignModuleRefs: refs can never reach zero, so releaseModule
		// will not finalize what this registry did not initialize.
		m := &pkcs11Module{ctx: ctx, path: path, refs: foreignModuleRefs}
		modules.byPath[path] = m
		return m, nil
	}

	m := &pkcs11Module{ctx: ctx, path: path, refs: 1}
	modules.byPath[path] = m

	return m, nil
}

// foreignModuleRefs is the reference count given to a module this process
// did not initialize. It is large enough that no plausible number of
// releases reaches zero, which is the point: this registry must not call
// C_Finalize on a module it did not call C_Initialize on.
const foreignModuleRefs = 1 << 30

// releaseModule drops one reference, finalizing and unloading the module
// when the last user is done with it.
func releaseModule(m *pkcs11Module) {
	if m == nil {
		return
	}

	modules.mu.Lock()
	defer modules.mu.Unlock()

	m.refs--
	if m.refs > 0 {
		return
	}

	delete(modules.byPath, m.path)
	m.ctx.Finalize()
	m.ctx.Destroy()
}

// loginSession logs the application in on session, treating "already
// logged in" as success.
//
// PKCS#11 login state belongs to the token and the application, not to the
// session: §6.7.5. So the second session this process opens on a slot gets
// CKR_USER_ALREADY_LOGGED_IN from C_Login, which is a statement that the
// precondition already holds rather than a failure - measured, not assumed,
// in TestPKCS11Module_SharedAcrossUsers.
//
// The mirror image is why nothing in this package calls C_Logout any more:
// it would log out every session on that token, not just the caller's. The
// token logs the application out by itself when its last session closes,
// which is the behaviour that was wanted.
func loginSession(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, pin string) error {
	err := ctx.Login(session, pkcs11.CKU_USER, pin)
	if err == nil {
		return nil
	}

	var code pkcs11.Error
	if errors.As(err, &code) && code == pkcs11.CKR_USER_ALREADY_LOGGED_IN {
		return nil
	}

	return err
}
