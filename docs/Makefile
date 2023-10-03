build: pipenv
	@# Run a production build of the documentation. Strict mode makes warnings fatal.
	pipenv run mkdocs build --strict

	@# Build main packages, discarding build output.
	go build -v ./...

	@# Build _test.go files containing Doc* functions, don't execute tests.
	go test -c -o /dev/null ./... >/dev/null

preview: pipenv
	pipenv run mkdocs serve

shell: pipenv
	pipenv shell

pipenv:
ifeq (, $(shell command -v pipenv 2> /dev/null))
$(error "pipenv is not installed, exiting..")
endif

.PHONY: pipenv
