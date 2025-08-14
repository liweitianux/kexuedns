NAME:=		Kexue DNS
PROGNAME:=	kexuedns

VERSION:=	$(shell sh aux/git-getversion.sh full --dirty)
VERSION_DATE:=	$(shell sh aux/git-getversion.sh date)
# Check more ldflags by 'go tool link'
LDFLAGS+=	-X $(PROGNAME)/config.version=$(VERSION) \
		-X $(PROGNAME)/config.versionDate=$(VERSION_DATE)
BUILD_ARGS+=	-v -trimpath -ldflags "$(LDFLAGS)"

# without debug
# LDFLAGS+= -s

.PHONY: all
all:
	go mod tidy
	go vet ./...
	env CGO_ENABLED=0 go build $(BUILD_ARGS)
	go test ./...

.PHONY: test
test:
	go test -v -coverprofile=coverage.out ./...
	# go tool cover -html=coverage.out

# Run all (-bench=.) benchmarks but skip all (-run='^$') unit tests.
.PHONY: bench
bench:
	go test -v -bench=. -run='^$$' ./...

all: ui/static/tailwindcss.js
ui/static/tailwindcss.js:
	curl -o $@ https://cdn.tailwindcss.com/3.4.13

ssl: $(PROGNAME).crt $(PROGNAME).key
$(PROGNAME).key:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out $@
$(PROGNAME).crt: $(PROGNAME).key
	openssl req -x509 -sha256 -days 3650 -subj '/CN=$(NAME)' -key $< -out $@
