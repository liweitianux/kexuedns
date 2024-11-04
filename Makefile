VERSION:=	$(shell sh aux/git-getversion.sh full --dirty)
VERSION_DATE:=	$(shell sh aux/git-getversion.sh date)
# Check more ldflags by 'go tool link'
LDFLAGS+=	-X main.version=$(VERSION) \
		-X main.versionDate=$(VERSION_DATE)
BUILD_ARGS+=	-v -trimpath -ldflags "$(LDFLAGS)"

ifneq (,$(wildcard ./vendor/modules.txt))
BUILD_ARGS+=	-mod vendor
endif

# without debug
# LDFLAGS+= -s -w

.PHONY: all
all:
	go mod tidy
	env CGO_ENABLED=0 go build $(BUILD_ARGS)

all: ui/static/tailwindcss.js
ui/static/tailwindcss.js:
	curl -o $@ https://cdn.tailwindcss.com/3.4.13
