# How trust works: a short course

Read time: about 10 minutes. No prior knowledge needed.

This course explains one question: **how does a wallet decide that an issuer or a verifier is who it says it is?** It describes the design we use on Fly dev. For configuration details, see [TRUST_AND_IDENTITY.md](TRUST_AND_IDENTITY.md). For what works today, see [WEBUILD_TRUST_PROGRESS.md](WEBUILD_TRUST_PROGRESS.md). The certificate rules come from ETSI TS 119 475 (V1.1.1, 2025-10).

## Lesson 1: the problem

A wallet holds your credentials. Two kinds of party talk to it:

- An **issuer** gives the wallet a credential.
- A **verifier** asks the wallet to show a credential.

Anyone can set up a server and claim to be a university or a bank. The wallet needs a way to check the claim before it hands over data or accepts a credential. That check is called **trust**.

## Lesson 2: the three things that make trust

1. **A certificate.** A signed file that says "this public key belongs to this name". The party signs its messages with the matching private key. The wallet checks the signature against the certificate.
2. **A chain.** A certificate is signed by another certificate, which is signed by another, up to a **root**. The wallet cannot judge a single certificate, but it can follow the chain to a root it already knows.
3. **A list of trusted roots.** The wallet, or a service that works for it, holds a list of roots it accepts. A chain that ends at a root on the list is trusted. Any other chain is not.

If you remember one sentence from this course, remember this one: **trust is a certificate chain that ends at a root on a list you accept.**

## Lesson 3: the two things a relying party can have

In the EU rules, any party that talks to a wallet is a **wallet-relying party (WRP)**. A verifier is one. An issuer is one too (lesson 5). A WRP is entered in a national register, and two things can then be issued to it:

| Name | Short for | What it is | What it says |
|---|---|---|---|
| **WRPAC** | Wallet-Relying Party Access Certificate | An X.509 certificate | "This key belongs to this WRP." |
| **WRPRC** | Wallet-Relying Party Registration Certificate | A signed token (JWT or CWT), not an X.509 certificate | "This WRP is registered, and it may ask for these attributes." |

The WRPAC answers *who are you*. The WRPRC answers *what may you ask for*.

- A WRP needs the WRPAC to be trusted at all.
- The WRPRC is optional. A Member State may choose to issue them. Where none is issued, the wallet reads the same information from the national register. We have no WRPRC yet.
- The two are linked by the WRP identifier: the `organizationIdentifier` in the WRPAC matches `sub.id` in the WRPRC. Names may differ. Only the identifier counts.
- A WRP may hold several WRPACs, for example one per server instance. They all identify the same WRP.
- A WRPRC has the JWT header `typ: rc-wrp+jwt` and carries its signer's certificate chain in `x5c`, like the signed requests in lesson 4. Its signer is a provider listed on a trusted list.

A WRPAC is issued by an authorised trust service provider (TSP). Our verifier requires these parts:

- a Subject Alternative Name (SAN) with a contact URI or email,
- a policy OID that marks it as a WRPAC,
- a validity period that has not ended.

The subject also carries the registered data of the WRP: `organizationName` (legal name), `countryName`, `organizationIdentifier` (the WRP identifier, for example `VATSE-...`) and `commonName` (trade name).

The verifier checks its own certificate against these rules at startup and refuses to start if one is missing.

## Lesson 4: how a wallet checks a verifier

The verifier does not send a plain request. It signs the request as a JWT, and it puts its certificate chain in the JWT header as `x5c`.

1. The verifier sends the wallet a signed request. Its `client_id` is `x509_san_dns:` followed by its host name, for example `x509_san_dns:sunet-vc-verifier.fly.dev`.
2. The wallet reads the chain from `x5c` and checks the signature on the request.
3. The wallet checks that the host name in `client_id` appears as a DNS name in the certificate's SAN. This ties the name to the certificate. A valid certificate for another name does not pass.
4. The wallet asks a **trust service** whether the chain is trusted. Lesson 6 describes that service.
5. If the answer is yes, the wallet shows the request to the user. If it is no, the wallet reports "Verifier is not trusted".

Check 3 matters because a chain that ends at a trusted root only proves that someone trusted issued the certificate. It does not prove the certificate belongs to this verifier.

## Lesson 5: how a wallet checks an issuer

The issuer works the same way, with one difference. It signs its **metadata**, the document that describes what it can issue, and puts its chain in the `x5c` header of that JWT. The wallet sends the chain to the trust service, as in lesson 4.

An issuer is a WRP with a role, called an **entitlement**. The EU list includes `PID_Provider`, `QEAA_Provider`, `Non_Q_EAA_Provider` and `PUB_EAA_Provider`. SUNET is listed as a Pub-EAA issuer in the WE BUILD list.

For a long time the wallet backend left out the chain when it asked the trust service about issuer metadata, so the answer was always no. This was fixed in go-wallet-backend v0.25.0 (pull request 541).

## Lesson 6: the trust service and the lists

Our trust service is **go-trust**. It speaks a small protocol called AuthZEN. The question and answer look like this:

- Question: "Here is a certificate chain. Is it trusted?"
- Answer: `decision: true` or `decision: false`.

go-trust decides from **trusted lists** only. The WE BUILD consortium publishes a **list of trusted lists** (a LoTL). It points to many lists. Some name the issuers of one kind, for example the Pub-EAA list. Others name the providers allowed to issue WRPACs, so they hold the CA root and not each verifier. go-trust loads these lists and answers from them.

There is no whitelist and no fallback. A chain that no loaded list covers gets `decision: false`. That is on purpose: when something fails, the cause is a list that is missing or did not load, and the go-trust log says which.

A list is itself signed, so go-trust must check the list's signature before it believes the list. For that it needs the **signer certificate** of each list, called a **trust anchor**. You give these to go-trust in a file named by `trust_anchor_bundle`.

Without an anchor for a list, go-trust skips that list. This is the main thing that can go wrong, and the main thing to look for in the logs.

Fly dev does this. Its go-trust config sets `verify_jws: true` and mounts `fly/dev/go-trust/trust-anchors.pem`, built with `lol` from the pinned LoTL signer. A list without a backed signer is skipped.

## Lesson 7: where things stand on Fly dev

The current status changes often. The file [WEBUILD_TRUST_PROGRESS.md](WEBUILD_TRUST_PROGRESS.md) is the source of truth. In short:

- The verifier has a WRPAC from the WE BUILD sandbox, and the chain verifies up to the WE BUILD root.
- The issuer is listed in the WE BUILD Pub-EAA list.
- go-trust releases 0.29.0 and later can verify the list signatures. We have not yet shown it loading the Pub-EAA list with verification on.
- Open: the wallet still reports "Verifier is not trusted", and we have no WRPRC yet.

## Exercises

Both exercises read a public Fly dev service. They change nothing.

1. **Look inside the issuer metadata.** This prints the signing algorithm, the type and the number of certificates in `x5c`:

   ```bash
   curl -s -H 'Accept: application/jwt' \
     https://sunet-vc-apigw.fly.dev/.well-known/openid-credential-issuer \
     | cut -d. -f1 | tr '_-' '/+' \
     | awk '{ while (length($0)%4) $0=$0"="; print }' \
     | base64 -d | jq -c '{alg,typ,x5c_certs:(.x5c|length)}'
   ```

   At the time of writing the answer is `{"alg":"ES256","typ":"openidvci-issuer-metadata+jwt","x5c_certs":2}`. Question: which lesson explains why the chain is in the header?

2. **Check that the trust service is up.**

   ```bash
   curl -s https://sunet-vc-go-trust.fly.dev/healthz
   ```

   You should see `{"status":"ok", ...}`. Question: this only shows that go-trust runs. What would you ask it to learn whether it trusts a given chain?

## Words to remember

| Word | Meaning |
|---|---|
| Certificate | A signed statement that a key belongs to a name. |
| Chain | Certificates linked by signatures, up to a root. |
| Root | The certificate at the top of a chain. |
| Trust anchor | A root, or a list signer, that you have decided to accept. |
| WRP | Wallet-relying party: any party that talks to a wallet, such as a verifier or an issuer. |
| WRPAC | The X.509 certificate that identifies a WRP. |
| WRPRC | A signed token (JWT or CWT) that says what a WRP may ask for. Optional. |
| TSP | Trust service provider: an authorised provider of certificates, listed on a trusted list. |
| Entitlement | A WRP's role, such as `PID_Provider` or `PUB_EAA_Provider`. |
| `x5c` | The JWT header field that carries a certificate chain. |
| LoTL | A list of trusted lists. |
| PDP | The service that answers "is this trusted?". Ours is go-trust. |
