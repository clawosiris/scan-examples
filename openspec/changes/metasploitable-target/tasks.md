## 1. Target environment

- [x] 1.1 Replace the lightweight HTTP target container in `docker-compose.yml` with `kirscht/metasploitable3-ub1404`.
- [x] 1.2 Define and wire a reasonable default TCP port set for the target, including SSH.
- [x] 1.3 Ensure the example CLI/env defaults and Compose wiring use the updated target definition.

## 2. Documentation and validation

- [x] 2.1 Update README/docs to explain the metasploitable target and default scanned ports.
- [x] 2.2 Update e2e tests/workflow expectations for the richer target and its findings output.
