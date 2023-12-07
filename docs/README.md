# epbf-go documentation

The documentation project uses Pipenv to manage its dependencies, which will
automatically create a Python virtualenv when invoked from this subdirectory.
Follow your distribution's documentation for installing `pipenv`. You may also
need `pyenv` to install a different Python version if your distribution doesn't
provide the version specified in the `Pipfile`.

Host a live preview of the documentation at http://127.0.0.1:8000:

`make preview`

Build the documentation, output to the site/ directory. This is a self-contained
production copy that can be uploaded to hosting.

`make build`

To enter the virtualenv with all the documentation's Python dependencies
installed:

`make shell`
