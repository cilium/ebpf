# epbf-go documentation

The documentation project uses Pipenv to manage its dependencies, which will
automatically create a Python virtualenv when invoked from this subdirectory.
Follow your distribution's documentation for installing `pipenv`. You may also
need `pyenv` to install a different Python version if your distribution doesn't
provide the version specified in the `Pipfile`.

To create a Python venv and install dependencies:

`$ pipenv install`

To enter the venv and use its corresponding interpreter:

`$ pipenv shell`

You may now run a development copy of the documentation locally:

`$ mkdocs serve`

.. or build all assets and output a full copy of the website ready for hosting:

`$ mkdocs build`
