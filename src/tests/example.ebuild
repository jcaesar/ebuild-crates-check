
CRATES="
adler32-1.0.4
arrayref-0.3.6
xattr-0.2.2
"

inherit cargo

SRC_URI="https://github.com/wasmerio/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz
	$(cargo_crate_uris ${CRATES})"
