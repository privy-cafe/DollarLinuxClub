# Copyright 2018 Haelwenn (lanodan) Monnier <contact@hacktivis.me>
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit git-r3

DESCRIPTION="Firefox configuration hardening"
HOMEPAGE="https://github.com/pyllyukko/user.js"
SLOT="0"
LICENSE="MIT"

EGIT_REPO_URI="${HOMEPAGE}.git"

src_prepare() {
	default

	cp "${FILESDIR}/local-settings.js" .

	sed -i 's/tests/test/' Makefile || die "Failed changing tests to test"
	sed -i '{/all:/ s/test//}' Makefile || die "Failed removing test from ``make all``"
	sed -i '{/test:/ s/acorn//}' Makefile || die "Failed removing acorn (unknown command) from test"
}

src_compile() {
	default
	emake systemwide_user.js
}

src_install() {
	insinto /usr/lib/firefox
	newins systemwide_user.js mozilla.cfg

	insinto /usr/lib/firefox/defaults/pref/
	doins local-settings.js
}
