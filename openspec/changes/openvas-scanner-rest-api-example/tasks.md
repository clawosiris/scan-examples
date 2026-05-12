## 1. Example implementation

- [x] 1.1 Add a Python client/example for the OpenVAS Scanner REST API using the community container.
- [x] 1.2 Add configuration conversion support for the community feed's **Full & Fast** scan configuration using `scannerctl`.
- [x] 1.3 Implement example commands or entrypoints for create, start, stop, results, and delete scan operations.
- [x] 1.4 Document required environment variables, certificates, feed location assumptions, and runtime parameters.

## 2. Containerized execution

- [x] 2.1 Add a Dockerfile for the example application.
- [x] 2.2 Ensure the image can run the example lifecycle in a reproducible way.

## 3. End-to-end validation

- [x] 3.1 Add Docker Compose fixtures for the community scanner environment and a metasploitable target.
- [x] 3.2 Add an e2e test that converts the Full & Fast config and exercises create, start, stop, results, and delete.
- [x] 3.3 Make the e2e test assert that results are returned in a stable, machine-checkable format.

## 4. CI automation

- [x] 4.1 Add a GitHub Actions workflow to build the example container.
- [x] 4.2 Add a GitHub Actions workflow job to stand up the compose environment and run the e2e test.
- [x] 4.3 Publish logs or artifacts needed to debug scanner or test failures.
