# DidServer

A Phoenix-based web server backed by a PostgreSQL database
to demonstrate delivery and updating of DID identities.

Also exposes a basic user account schema for roaming identities
that might be extended to support both ActivityPub and
the Bluesky AT Protocol.

Both did:web and did:plc methods are implemented.

To start your Phoenix server:

- Run `mix setup` to install and setup dependencies
- Start Phoenix endpoint with `mix phx.server` or inside IEx with `iex -S mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

Ready to run in production? Please [check our deployment guides](https://hexdocs.pm/phoenix/deployment.html).

## Learn more

- Official website: https://www.phoenixframework.org/
- Guides: https://hexdocs.pm/phoenix/overview.html
- Docs: https://hexdocs.pm/phoenix
- Forum: https://elixirforum.com/c/phoenix-forum
- Source: https://github.com/phoenixframework/phoenix

## Identity ideas from Bluesky

Bluesky says that out of the box they support both the did:web and did:plc
methods to resolve identities. The did:web method is only supported at
the domain level, with the URL of

- `https://[<username>.]<domain.com>/.well-known/did.json`

That is, no path elements in the DID are supported.

In addition Bluesky will use either a DNS TXT records or a well-known web
address, to resolve the DID for a particular custom domain or sub-domain.
To support more than one user at a hosted domain probably would require
staging per-user sub-domains through a DNS service and web server that
can proxy and respond correctly to any request for sub-domains like
`<username>.<domain.com>`.

As of July 5, 2023, Bluesky is now in the per-user domain reselling
business, so they obviously believe that this is something users
will want to take adavantage of.

More information is here:

- [ATProtocol: Identity](https://atproto.com/guides/identity)
- [did-method-plc repository](https://github.com/bluesky-social/did-method-plc)
- [How to set your domain as your handle](https://blueskyweb.xyz/blog/4-28-2023-domain-handle-tutorial)

## "Persona" and identity model

Discussion from https://matrix.to/#/!vpdMrhHjzaPbBUSgOs:matrix.org/$Gc0872Gfhxin3tY66DTigS9CkSnhNNroS14hAwNMkCM

I am experimenting with an idea of multiple user "personas" all under the
umbrella of a single identity, which is represented by a DID.

Each persona has its own display name, user name, domain name, and profile
information (description, avatar, banner). The schema for the persona is the
`DidServer.Accounts.Account` module.

The identity DID holds the single hashed password for authentication. Any of
the personas linked to the DID can use this password for authentication.
The schema for the DID is the `DidServer.Identities.Key` module.

The thing I'm finding difficult to understand from the Bluesky protocols,
is where the private keys for the "signing key" (a public-private keypair)
and for the "rotation keys" (each one a keypair) come from, and if and where
they need to be stored.

The [indigo repository](https://github.com/bluesky-social/indigo) seems to
use a single, server-wide signing key, read at start up from a "server.key"
file on disk in the function `cmd.laputa.main.run`.

When user accounts are created in the `pds.handlers.handleComAtprotoServerCreateAccount`
function, the recovery key is optional and is passed in via arguments. Its
DID (public key, potentially empty) is stored with the user, and if the key
is not given in the command input, the server-wide signing key is used as
the single rotation key for the DID that is created for the user.

The command-line command `gosky newAccount` does not parse or send a recovery
key, so in effect the user always has an empty string its `recoveryKey` field.

To sign documents and verify documents, indigo uses a `KeyManager` interface.
When signing, the KeyManager must hold a valid private keypair in its
`signingKey` field, although this seems never to be set. Instead, the only
signing is inside the `api.plc.CreateDID` function, which gets passed the
server-wide signing key as an argument.

To verify DID documents, the document is resolved and the KeyManager extracts
the public key from the "#atproto" verification method.

Thus no private key is ever stored in a database, but is it safe to use a
single site-wide key this way?

### More identifier / identity discussion

See https://socialhub.activitypub.rocks/t/alsoknownas-and-acct/3132/20

Argues for using an `xrd:aliases` property in an Actor to describe other 
identifiers in an ordered list.

The [bovine project](https://codeberg.org/helge/bovine) can store 
multiple "keypairs", for a given user (the model class is 
`BovineActorKeyPair`). There are three types of keypair:

```python
# Type 1 - RSA PCKS#8 PEM encoded keypair, name is always 'serverKey'.
{
  name: 'serverKey', 
  public_key: '-----BEGIN PUBLIC KEY-----\n...',
  private_key: '-----BEGIN PRIVATE KEY-----\n...'
}

# Type 2 - Account handle, name is always 'account'.
{
  name: 'account', 
  public_key: 'acct:user@domain', 
  private_key: None
}

# Type 3 - Ed25519 public key as a Multikey-encoded DID
# User can supply key name for an existing DID, or the
# bovine_tool can create new DID and name will be 'key-from-tool'.
{
  name: 'user-supplied-key-name', 
  public_key: 'did:key:xxx', 
  private_key: None
}
```

One each of keypair types 1 and 2 are created when an account is registered. 
Any number of key pair type 3 (DID) can be added after registration.
The user must maintain and supply the secret (Ed25519 private key) for 
each type 3 keypair. So an actor can have multiple DIDs associated with
a single account.

Bovine's WebFinger endpoint can look up both the type 2 and type 3
resources and returns the actor's "rel=self" URL.

### Reconciling different roots of identity

https://socialhub.activitypub.rocks/t/reconciling-different-roots-of-identity/3399/7

by_caballero:

I would prefer to think of a keypair (whether expressed as a did:key, 
a multikey, a did:pkh, and/or as any other form of did) as a property 
of the account that can be updated over time–I don't believe this is 
explicit enough in ActivityPub, but it seems implied, if nothing else, 
by the nature of ids in Linked Data generally as roots of identity. 
Keypairs being secondary properties that change over time is, I would 
argue, the dominant model in most software today...

Assuming an account can update keys periodically and that today's keys 
can only be gotten by querying the server in its id feels a lot simpler 
than any alternative, particularly given status quo implementation-wise.

Thinking of the keypair as a property of the account also opens up 
"byo authenticator" patterns, i.e. replacing the public key in the 
profile without generating a new private key or importing an external 
private key, by proving control of it (e.g. signing an arbitrary 
confirmation-message payload and producing a verifiable receipt at 
time of import/association). 

For a fun example of "byo authenticator" see [this project](https://dostr-eth.github.io/resources/#private-key-derivation) 
that uses an Ethereum wallet as an authenticator for a Nostr account!

This delegation to an external authenticator (such as Authy or 
Microsoft Authenticator, or other cryptographic wallets that can 
sign arbitrary messages) could align quite well with the approach 
in FEP-521a and FEP-c390.

As for the alsoKnownAs chaos, I am convinced that the rel="me" system 
makes the most sense for one logical human maintaining multiple accounts 
over time, which is of course a major usability feature of modern social 
media anyways independent of migration and tombstoning.

What I would propose for the interrelated problems of migration and 
tombstoning is something very different and more hierarchical, which is 
closer to the DID semantic controller, i.e., that identifier HAS AUTHORITY 
OVER this account/identifier. For example, it could mean:

  * this authenticator/signer/private key has been authorized to sign for 
    the subject anywhere its signatures are accepted,
  * this external identifier/authN mechanism is authorized to authenticate 
    migration requests,
  * this external AuthN is authorized to tombstone this account, after 
    migration, or keep it as a rel="me",
  * if this server bans the user and freezes/closes their account, this 
    authority has already been externalized and migration can still 
    happen if records of the authorization can still be verified.

If instances can get OK with that pre-authorization/authority-export which 
overrides, say, a ban or a boot then maybe AP isn't locked into the 
authority of the webserver forever.

trwnh:

However, we also need to establish "same controller", "external owner", 
"same logical person" or at the very least "is permitted to send 
activities partially or fully on my behalf, particularly the Move 
activity". 

Some proposals:

  * check for alsoKnownAs (Mastodon usage, not DID definition)
  * check for rel="me" or some other property making the same claim 
    (unambiguous, but not currently supported by anyone since 
    alsoKnownAs is historically used in a similar/same way)
  * check for a cryptographic signature that can be verified with 
    the same public key as was last known (requires careful handling 
    for edge cases, plus agreement that keys are meaningful sources 
    of identity)

Note that in the immediate above statement, we must differentiate 
between "same controller" and "permitted to send activities on my behalf"; 
the former might imply the latter, but the latter does not necessarily 
imply the former. We might grant or delegate or give escrow to some 
other controller who can act "on behalf of" us. for example, an "instance 
actor" representing a server or domain, which we are currently using. 

With such a scheme, it becomes possible to eliminate the shell game 
taking place within current http/ld signatures–rather than the server 
generating keypairs for every actor and then puppeting those actors, 
the server could send messages "on behalf of" the actors it "owns" or 
"is responsible for". The exact nature of the relationship between 
any actor and their server (or any other actor) should be possible to 
clarify along these lines, and to place limits on what this relationship 
does or does not allow them to do.

by_caballero:

I would just like to emphasize what I meant by "heirarchical" (controller) 
as opposed to "horizontal" (rel="me" or alsoKnownAs) in case that didn't 
make sense or answer the question as much as I thought it did. [Those diagrams](https://dostr-eth.github.io/resources/#private-key-derivation)
I linked to above of a Nostr client based on Sign In With 
Ethereum 2 is a good example of a delegation pattern that could be 
relevant here: the client basically generates a deterministic Nostr 
private key to use on behalf of the user after receiving a delegation 
message signed by an EVM/secp key that the user controls elsewhere. 

This means the Nostr key is downstream of that key "external" to it, 
which is its controller in DID terms. Thus, a "custodial" (well, 
technically deterministic/symmetrical, but at the very least 
server-side-generated) Nostr private key is signing things on behalf 
of a Nostr "actor" that has an external controller which outranks it 
(the ethereum private key it doesn't own). This is not an alsoKnownAs 
or rel="me" peer, but a greater authority.

### Deterministic server-generated key pairs

1. Matrix "recovery key". `Passphrase + user info + algorithm + salt + iterations + bits => {algorithm, salt, iterations, bits, private key}`.

2. Dostr. `Ethereum keypair + username + message => HKDF => private key`.

### Discussion of DIDs and identity proofs

https://socialhub.activitypub.rocks/t/fep-c390-identity-proofs/2726/49

The next step is improving usability and security of account migration process based on FEP-c390. It would be also interesting to experiment with client-side activity signing (AP C2S + FEP-8b32 + FEP-c390).

### Non-blockchain decentralized identifiers

[did:github](https://docs.github-did.com/did-method-spec/) - Uses GitHub repositories.
Potentially this could be expanded to include gitolite, gitea, codeberg, etc., systems 
that expose URLs like `https://raw.githubusercontent.com/USERNAME/ghdid/master/index.jsonld`. 
This method relies on trusting GitHub’s authentication when making updates 
to a DID document, but a user MAY chose to use Linked Data Signatures via 
the proof field of their DID document for a strong verifiable cryptographic proof.

[did:ipid](https://did-ipid.github.io/ipid-did-method/) - Based on IPFS.

[did:orb](https://trustbloc.github.io/did-method-orb/) - Uses Sidetree protocol
content-addressable storage, IPFS, ActivityPub on a decentralized network of servers 
and witnesses. The witnesses give signed timestamps to operations, to resolve
[late publishing conflicts](https://identity.foundation/sidetree/spec/#late-publishing).

AP object types are "AnchorCredential", "AnchorEvent", "AnchorLink", "AnchorReceipt", "Collection", "CollectionPage", "Link", "OrderedCollection", "OrderedCollectionPage", "Service", "VerifiableCredential".

AP activities are  "Accept/Follow,Invite,Offer", "Announce/AnchorEvent", "Create/AnchorEvent", "Follow", "Invite/AnchorWitness",  "Like", "Offer", "Reject/Follow,Invite,Offer", "Undo/Follow,Invite,Like".

Collections kept in DB are "Activities", "AnchorLinksets", "Followers", "Following", "Inbox", "Liked", "Likes", "Outbox", "PublicOutbox", "Shares", "Witness", "Witnessing".

Link is 
	Anchor   *vocab.URLProperty `json:"anchor"`
	Profile  []*Reference       `json:"profile"`
	Author   []*Reference       `json:"author,omitempty"`
	Item     []*Item            `json:"item,omitempty"`
	Original []*Reference       `json:"original,omitempty"`
	Related  []*Reference       `json:"related,omitempty"`
	Replies  []*Reference       `json:"replies,omitempty"`
	Up       []*Reference       `json:"up,omitempty"`
	Via      []*Reference       `json:"via,omitempty"`

Reference is
	HRef *vocab.URLProperty `json:"href"`
	Type string             `json:"type,omitempty"`

[did:peer]

[did:schema](https://github.com/51nodes/schema-registry-did-method/blob/master/README.md) - Uses public IPFS (susceptible to attack) or evan.network IPFS (better security).

## Implmentation: user model and authentication

The "user" (`DidServer.Accounts.User`), which is able to log in with a password
or WebAuthn passkey, and which creates and verifies session tokens, binds
an "account" (`DidServer.Accounts.Account`; the user's account and profile on
a specific internet domain or instance) to a DID. The DID (`DidServer.Identities.Key`)
holds a single hashed password and a private key, held in a key vault
(extremely insecure in this development demo). In production, the key vault
should be kept in an separate secure storage.

`User`s can store multiple WebAuthn credentials (`DidServer.Identities.Credential`)
on different devices.

I don't know enough about HSMs like the Yubikey or Apple's iCloud Keychain
to understand how or if you can programmatically use these securely stored
keypairs to sign a document. AFAICT, the access granted to these stored keys
by browsers supporting the Credential Management and Web Authentication APIs
is limited to authentication challenges and attestations; the private key
cannot be used for signing arbitrary hashes.

Mulitple `User`s can be represented in the same DID (as they are listed in the
DID document's `alsoKnownAs` field), and thus they all share the same password,
but they will have distinct WebAuthn passkeys.

## did:web method support

(Development) URLs for fetching DID documents are, e.g.

For a DID like `did:web:localhost%3A4000`:

- http://localhost:4000/.well-known/did.json

For a DID with path elements like `did:web:localhost%3A4000:user:alice`
(not supported by Bluesky):

- http://localhost:4000/users/alice/did.json

## did:plc method support

The `https://plc.directory` described in the did-method-plc README
is served at `http://localhost:4000/plc` in the development server,
so URLs for fetching DID documents are, e.g.

- http://localhost:4000/plc/did%3Aplc%3A4heftswx5xresjexdo4nnpmj
