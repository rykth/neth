package cert

import "encoding/asn1"

// Private OID arc for neth extensions: 1.3.6.1.4.1.65535.1.*
// 65535 is used as a stand-in PEN for this project.
var (
	oidVpnIP         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65535, 1, 1}
	oidGroups        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65535, 1, 2}
	oidCurve25519Key = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65535, 1, 3}
)
