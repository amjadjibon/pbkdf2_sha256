VERSION = "0.0.1"
change-version:
	@echo $(VERSION)>VERSION

test:
	go test -race ./... -v

update-module:
	go get -v golang.org/x/crypto

