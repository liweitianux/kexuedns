NAME:=		kexuedns

VERSION:=	$(shell sh aux/git-getversion.sh full --dirty)
# Check more ldflags by 'go tool link'
LDFLAGS+=	-X main.version=$(VERSION)
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
