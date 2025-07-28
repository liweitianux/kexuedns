VERSION:=	$(shell sh aux/git-getversion.sh full --dirty)
VERSION_DATE:=	$(shell sh aux/git-getversion.sh date)
# Check more ldflags by 'go tool link'
LDFLAGS+=	-X main.version=$(VERSION) \
		-X main.versionDate=$(VERSION_DATE)
BUILD_ARGS+=	-v -trimpath -ldflags "$(LDFLAGS)"

# without debug
# LDFLAGS+= -s -w

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
