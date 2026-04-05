# Publishing `macfw`

This project publishes Python distributions through GitHub Actions using PyPI Trusted Publishing.

## One-time setup

### 1. Confirm the package metadata

The package name and version live here:

- `pyproject.toml`
- `macfw/__init__.py`

Build locally before the first release:

```bash
python3 -m pip install --upgrade build twine
python3 -m build
twine check dist/*
```

### 2. Configure Trusted Publishers

Create Trusted Publishers on both PyPI and TestPyPI.

PyPI:

- Owner: `tudoujunha`
- Repository: `macfw`
- Workflow: `publish-pypi.yml`
- Environment: `pypi`

TestPyPI:

- Owner: `tudoujunha`
- Repository: `macfw`
- Workflow: `publish-testpypi.yml`
- Environment: `testpypi`

The workflow files live in:

- `.github/workflows/publish-pypi.yml`
- `.github/workflows/publish-testpypi.yml`

## TestPyPI release flow

Use TestPyPI first when validating a new release pipeline.

1. Push the current branch to GitHub.
2. Open the `Publish TestPyPI` workflow in GitHub Actions.
3. Run it manually with `workflow_dispatch`.
4. Confirm the package appears on TestPyPI.
5. Test installation:

```bash
python3 -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple macfw
```

## PyPI release flow

After TestPyPI succeeds:

1. Update the version in:
   - `macfw/__init__.py`
   - `pyproject.toml`
2. Commit the release version.
3. Create and push a Git tag:

```bash
git tag -a v0.1.1 -m "macfw v0.1.1"
git push origin main
git push origin v0.1.1
```

4. GitHub Actions will build the wheel and sdist, then publish to PyPI.

## Notes

- The PyPI workflow publishes on tag pushes matching `v*`.
- The TestPyPI workflow is manual on purpose.
- If the package name is already taken on PyPI, publishing will fail until the name is changed.
- The package is meant to be installed with `pipx install macfw` once it is on PyPI.
