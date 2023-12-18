module saml-test-idp

go 1.20

require (
	github.com/crewjam/saml v0.4.13
	golang.org/x/crypto v0.17.0
)

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/goxmldsig v1.3.0 // indirect
	github.com/zenazn/goji v1.0.1 // indirect
)

replace github.com/crewjam/saml => github.com/weiiwang01/saml v0.0.0-20230826085246-5ac2afa0b4ea
