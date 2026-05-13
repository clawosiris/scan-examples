# Authenticated SSH e2e scan

Issue #12 asks for the metasploitable e2e test to run an authenticated SSH scan. The bundled target image supports setting the `msfadmin` password through the `PASS` environment variable, and the scanner API target payload supports SSH username/password credentials.

## Changes

- Explicitly set the metasploitable target password in Compose.
- Add SSH credential fields to the scan target skeleton used for scannerctl conversion.
- Expose CLI/environment knobs for the SSH username, password, and port while defaulting to the bundled target credentials.
- Document the authenticated e2e behavior.
