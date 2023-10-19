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
	@echo "pipenv shell"
	@exec pipenv shell

pipenv:
ifeq (, $(shell command -v pipenv 2> /dev/null))
$(error "pipenv is not installed, exiting..")
endif

	@# Ensure a venv and install dependencies from Pipfile.lock. Buffer stdio
	@# and display it on error as pipenv uses stdin and stderr arbitrarily.
	@echo "pipenv sync"
	@out=`pipenv sync 2>&1` || echo "$${out}"

.PHONY: pipenv
