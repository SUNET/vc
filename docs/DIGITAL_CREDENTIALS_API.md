# W3C Digital Credentials API Integration

## Overview

The verifier now supports the **W3C Digital Credentials API** for browser-based credential presentation. This modern approach allows users to present digital credentials directly from their browser's built-in wallet, providing a seamless user experience without requiring QR code scanning.

## What is the W3C Digital Credentials API?

The [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/) is a browser API that enables web applications to request verifiable credentials from digital wallets. It provides:

- **Native browser integration** - No separate wallet app required
- **Improved UX** - Present credentials with a single click
- **Strong security** - Browser-mediated credential exchange
- **Format flexibility** - Supports SD-JWT and mdoc formats

## Architecture

```
┌─────────────────┐                    ┌──────────────────┐
│  Relying Party  │                    │    Verifier      │
│    (Your App)   │                    │   (This Service) │
└────────┬────────┘                    └────────┬─────────┘
         │                                      │
         │ 1. Standard OIDC authorize           │
         │─────────────────────────────────────>│
         │                                      │
         │ 2. Render authorize.html             │
         │<─────────────────────────────────────│
         │                                      │
    ┌────▼────────────────────────────────┐    │
    │   Browser (User's Device)           │    │
    │                                     │    │
    │  3. navigator.credentials.get()     │    │
    │  ┌──────────────────────────┐       │    │
    │  │  Built-in Wallet         │       │    │
    │  │  (Browser Credentials)   │       │    │
    │  └────────────┬─────────────┘       │    │
    │               │ 4. User approves    │    │
    │               └──────┐              │    │
    │                      │              │    │
    │  5. POST vp_token to direct_post    │    │
    │─────────────────────────────────────────>│
    │                                     │    │
    │  6. Redirect with auth code         │    │
    │<─────────────────────────────────────────│
    └─────────────────────────────────────┘    │
         │                                      │
         │ 7. Exchange code for tokens          │
         │─────────────────────────────────────>│
         │                                      │
         │ 8. ID token with verified claims     │
         │<─────────────────────────────────────│
         │                                      │
```

### Key Benefits for RPs

1. **Zero changes required** - RPs use standard OIDC authorization code flow
2. **No wallet knowledge needed** - Verifier handles all wallet interactions
3. **Automatic fallback** - QR code flow works when DC API is unavailable
4. **Standard claims** - Receive verified claims in standard OIDC ID tokens

## Configuration

Enable the W3C Digital Credentials API in your `config.yaml`:

```yaml
verifier:
  digital_credentials:
    enabled: true
    use_jar: true
    preferred_formats:
      - "vc+sd-jwt"
      - "dc+sd-jwt"
      - "mso_mdoc"
    response_mode: "dc_api.jwt"
    allow_qr_fallback: true
    deep_link_scheme: "openid4vp://"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable W3C Digital Credentials API support |
| `use_jar` | boolean | `false` | Use JWT Authorization Request (JAR) for security |
| `preferred_formats` | array | `["vc+sd-jwt"]` | Credential formats in preference order |
| `response_mode` | string | `"direct_post"` | How wallet sends response: `dc_api.jwt`, `direct_post.jwt`, `direct_post` |
| `allow_qr_fallback` | boolean | `true` | Auto-fallback to QR code if DC API unavailable |
| `deep_link_scheme` | string | `"openid4vp://"` | Deep link scheme for mobile wallets |

### Supported Formats

- **`vc+sd-jwt`** - SD-JWT Verifiable Credentials (W3C standard)
- **`dc+sd-jwt`** - Digital Credentials SD-JWT variant
- **`mso_mdoc`** - ISO/IEC 18013-5 mobile driving license format

## UI Customization

Customize the authorization page appearance:

```yaml
verifier:
  authorization_page_css:
    title: "Employee Verification"
    subtitle: "Present your employee credential to access this service"
    theme: "blue"                    # light, dark, blue, purple
    primary_color: "#1e40af"         # Override theme color
    secondary_color: "#1e3a8a"
    logo_url: "https://example.com/logo.png"
    custom_css: |
      .container { max-width: 600px; }
    # css_file: "/path/to/custom.css"
```

### Theming Options

| Theme | Primary Color | Secondary Color | Best For |
|-------|--------------|-----------------|----------|
| `light` | `#3182ce` | `#2c5282` | Default, general purpose |
| `dark` | `#3182ce` | `#2c5282` | Dark mode preference |
| `blue` | `#3182ce` | `#2c5282` | Corporate, professional |
| `purple` | `#805ad5` | `#553c9a` | Creative, modern |

## Browser Support

The W3C Digital Credentials API is currently supported in:

- **Chrome/Edge 116+** (with experimental flag)
- **Safari 17+** (partial support)
- **Firefox** (planned)

**Graceful Degradation**: When the API is not available, the authorization page automatically shows the QR code as a fallback. No user interaction is broken.

## Security Considerations

### JWT Authorization Request (JAR)

When `use_jar: true`, the verifier:

1. Creates a signed JWT containing the authorization request
2. Wallet validates the signature before processing
3. Prevents parameter tampering and injection attacks

**Recommendation**: Always enable JAR in production environments.

### Response Modes

| Mode | Security | Use Case |
|------|----------|----------|
| `dc_api.jwt` | Encrypted JWT | Maximum security, browser-based wallets |
| `direct_post.jwt` | Signed JWT | Moderate security, standard wallets |
| `direct_post` | Plain form | Legacy support, testing only |

**Recommendation**: Use `dc_api.jwt` for production deployments with DC API.

## Format Negotiation

The verifier requests credentials in **order of preference**:

```yaml
preferred_formats:
  - "vc+sd-jwt"    # Try this first
  - "dc+sd-jwt"    # Fallback to this
  - "mso_mdoc"     # Last resort
```

The wallet selects the **first supported format** and returns credentials accordingly. The verifier automatically extracts claims from any format.

### Format-Specific Processing

- **SD-JWT formats** (`vc+sd-jwt`, `dc+sd-jwt`): Claims extracted from disclosed fields
- **mdoc format** (`mso_mdoc`): Claims extracted from ISO 18013-5 data elements

## Relying Party Integration

### Standard OIDC Flow (No Changes)

```javascript
// Your RP code remains unchanged
window.location = 'https://verifier.example.com/authorize?' + 
  'response_type=code&' +
  'client_id=your_client_id&' +
  'redirect_uri=https://your-app.com/callback&' +
  'scope=openid employee_id&' +
  'state=xyz123';

// User presents credential via DC API or QR code
// Your callback receives the authorization code

// Exchange code for tokens
const tokenResponse = await fetch('https://verifier.example.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://your-app.com/callback',
    client_id: 'your_client_id',
    client_secret: 'your_secret'
  })
});

const { id_token } = await tokenResponse.json();
// id_token contains verified claims from the credential
```

### What Happens Behind the Scenes

1. **Browser Detection**: Page checks if `navigator.credentials` API exists
2. **Format Selection**: Sends `vp_formats` preference to wallet
3. **User Consent**: Browser shows native credential selection UI
4. **Credential Presentation**: Wallet returns VP token to verifier
5. **Claim Extraction**: Verifier maps credential claims to OIDC claims
6. **Code Issuance**: Returns standard OIDC authorization code to RP

## Credential Display & Debugging

The verifier includes an optional **credential display feature** that shows users the credential details before completing authorization. This serves two purposes:

1. **Debugging Tool** - Developers can see the raw credential and extracted claims
2. **Transparency/Consent** - Users can review what data is being shared with the RP

### Configuration

```yaml
verifier:
  credential_display:
    enabled: true                   # Show checkbox on authorization page
    require_confirmation: false     # Make it optional (true = mandatory)
    show_raw_credential: true       # Display raw VP token/JWT
    show_claims: true               # Display parsed claims
```

### How It Works

1. **Authorization Page**: When enabled, users see a checkbox "Show credential details before completing authorization"
2. **User Choice**: 
   - If unchecked (default): Normal flow - credential sent directly to RP
   - If checked: User is redirected to credential display page after presenting credential
3. **Display Page**: Shows:
   - **Parsed Claims** - The exact claims that will be sent to the RP in the ID token
   - **Raw Credential** (optional) - The full VP token in JWT or mdoc format for debugging
   - **RP Information** - Which service is requesting the data
4. **Confirmation**: User must click "Confirm & Continue" to proceed, or "Cancel" to abort

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Show credential display checkbox on authorization page |
| `require_confirmation` | boolean | `false` | Make credential display mandatory (checkbox pre-checked and disabled) |
| `show_raw_credential` | boolean | `false` | Display raw VP token/credential in JWT or mdoc format |
| `show_claims` | boolean | `true` | Display parsed claims that will be sent to RP |

### Use Cases

**For Developers**:
- Debug credential parsing issues
- Verify claim mapping is working correctly
- Inspect raw credential structure
- Test with different credential formats

**For Production** (Optional):
- Add transparency layer showing users exactly what's shared
- Provide additional consent step beyond wallet approval
- Help users understand credential contents
- Debugging specific user issues

**Recommendation**: 
- **Development**: `enabled: true, require_confirmation: false, show_raw_credential: true`
- **Production**: `enabled: false` (unless regulatory requirements demand additional consent)
- **Support/Debug**: Enable on demand for specific sessions

### Security Note

When `show_raw_credential: true`, the full credential (including potentially undisclosed fields in SD-JWTs) may be visible. This is intentional for debugging, but be aware:

- Raw credentials may contain more data than what's disclosed to the RP
- Only enable in trusted environments or for debugging
- The RP still only receives the disclosed claims in the ID token

## Testing

### Local Development

1. **Enable Chrome Experimental Features**:
   - Navigate to `chrome://flags`
   - Enable "Web Authentication API for Digital Credentials"
   - Restart browser

2. **Configure Test Credentials**:
   ```yaml
   verifier:
     digital_credentials:
       enabled: true
       use_jar: false              # Easier debugging
       response_mode: "direct_post"  # Simpler for testing
       preferred_formats: ["vc+sd-jwt"]
   ```

3. **Test with QR Fallback**:
   - Open authorization page in non-supporting browser
   - Verify QR code appears automatically
   - Scan with mobile wallet app

### Integration Testing

The verifier includes automated tests for:

- DC API request object generation
- Format negotiation (mdoc vs SD-JWT)
- Response handling (encrypted JWT and form-encoded)
- Graceful fallback scenarios

Run tests:
```bash
make test
```

## Troubleshooting

### Issue: DC API Button Not Showing

**Check**:
1. `digital_credentials.enabled: true` in config
2. Browser supports `navigator.credentials.get()`
3. HTTPS enabled (required for secure contexts)

**Solution**: Enable experimental flags or use QR fallback

### Issue: "NotSupportedError" from Wallet

**Cause**: Wallet doesn't support requested credential format

**Solution**: Add more formats to `preferred_formats`:
```yaml
preferred_formats:
  - "vc+sd-jwt"
  - "dc+sd-jwt"
  - "mso_mdoc"  # Add this for broader compatibility
```

### Issue: Encrypted Response Failing

**Note**: Encrypted response (`dc_api.jwt`) decryption is **not yet implemented**. Use `direct_post` mode for now:

```yaml
response_mode: "direct_post"
```

**Planned**: Full JARM decryption support in future release.

## Roadmap

- [x] Basic DC API integration
- [x] Multi-format support (SD-JWT, mdoc)
- [x] JAR (signed request objects)
- [x] CSS customization
- [ ] Encrypted response decryption (JARM)
- [ ] Enhanced format-specific claim mapping
- [ ] mdoc device signature validation
- [ ] Browser wallet API v2 support

## References

- [W3C Digital Credentials API Specification](https://wicg.github.io/digital-credentials/)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [SD-JWT Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt)
- [ISO 18013-5 mdoc](https://www.iso.org/standard/69084.html)
- [JWT Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)

## Support

For questions or issues:
- Open an issue on GitHub
- Check existing documentation in `/docs`
- Review example configuration in `config.yaml`
