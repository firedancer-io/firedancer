**Quickstart***

This quickstart guide allows you to run CodeQL queries against the
GitHub-hosted CodeQL database for the Firedancer repo.  The DB is
updated nightly, so source code changes are not picked up immediately.

This should be run **locally**, not in, e.g., VSCode Remote SSH.

Requirements:
- Visual Studio Code Installation
- Access to firedancer-io org

Steps:
- Download codeql-bundle-xxx.tar.gz from here https://github.com/github/codeql-action/releases
- Install `codeql` to `$PATH` (edit `~/.profile`, etc)
- Optional: Fix CA certs if behind corporate proxy
  - `cd ~/opt/codeql/java/tools/osx64/jdk-extractor-java/lib/security`
  - `keytool -importcert -file root_ca.pem -alias customca -keystore cacerts -storepass changeit`
- Reload VSCode so it picks up `codeql` in `$PATH`
- Install vscode-codeql extension
- Select CodeQL tab
- Download `firedancer-io/firedancer` CodeQL using GitHub, select `C / C++` as language
- Wait for download to finish
- Right click database, hit 'Add Database Source to Workspace'

**Creating a database from scratch**

Alternatively, you can create your own CodeQL database from scratch.
You will have to re-create the database whenever you change the source.

```
BUILDDIR=codeql codeql database create --language=c --command='make -j' ../db-path
```

Objects will be at `build/codeql`
