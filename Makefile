# incredigo — developer tasks. See docs/ROADMAP.md (M1) for the tooling contract.
#
# The go test suite is self-contained (fake gopass/psql binaries, httptest
# emulators, in-process SSH servers); it needs bash + openssl on PATH but no live
# services. LIVE-VM driver proofs are separate and run via `make vm-proof`.

GO      ?= go
BIN     ?= /tmp/incredigo
PKG     ?= ./...
# Coverage floors are NOT yet enforced in CI: rotate (76%), policy (66%) and tui
# (57%) are still below target (ROADMAP M1). `make cover` reports per-package
# numbers; flip `check-cover` on once those packages are lifted.
COVER_FLOOR ?= 70

.PHONY: all build vet test race cover check-cover map vm-proof clean

all: build vet test

build:
	$(GO) build $(PKG)
	$(GO) build -o $(BIN) ./cmd/incredigo

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test $(PKG)

race:
	$(GO) test -race $(PKG)

# Per-package coverage report (no gate).
cover:
	$(GO) test -cover $(PKG)

# Advisory coverage gate: prints any PACKAGE below COVER_FLOOR. Does not fail the
# build yet (see note above). Wire into CI once safety-critical packages are green.
check-cover:
	@$(GO) test -cover $(PKG) | awk -v floor=$(COVER_FLOOR) \
	  '/coverage:/ { for (i=1;i<=NF;i++) if ($$i=="coverage:") { c=$$(i+1); gsub("%","",c); \
	     if (c+0 < floor) printf "  UNDER %d%%: %-34s %s%%\n", floor, $$2, c } }'

# Regenerate the visual project map (build artifact, gitignored).
map:
	@command -v project-map >/dev/null 2>&1 && project-map . || \
	  echo "project-map not on PATH — regenerate incredigo-map.html with the /project-map skill"

# Run a LIVE-VM rotation proof for one driver against the Multipass sandbox.
# Usage: make vm-proof DRIVER=postgres  (lab scripts live under lab/, ROADMAP M0).
vm-proof:
	@test -n "$(DRIVER)" || { echo "usage: make vm-proof DRIVER=<name>"; exit 2; }
	@echo "vm-proof for $(DRIVER): see docs/ROTATION-REAL-CRED-RUNBOOK.md and lab/ (ROADMAP M0/M1)"

clean:
	rm -f $(BIN) /tmp/incredigo.cov
