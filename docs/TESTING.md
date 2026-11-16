# KVM Manager testing

## Lightweight host inventory UI logic

Run the focused inventory tests from the repository root:

```sh
yarn test:ui
```

These Node tests cover host health counts, stale-check handling, display name
versus detected hostname, and combining inventory search/state filters. They
run offline and do not connect to Rancher or any host. They complement the API
suite; they are not a browser-based Vue rendering test.

## Offline API regression suite

Run the API regression tests from the repository root:

```sh
python3 -m pip install -r service/requirements.txt
python3 -m unittest discover -s service/tests -v
```

The tests use a temporary SQLite database and mock Rancher identity and host
discovery. They do not contact Rancher, a KVM host, libvirt, Cockpit, or S3.
The test encryption key and host details are disposable fixtures only.

The suite checks unauthenticated access, viewer and scoped-role boundaries,
password and optional key host-import handling, SSH host-key persistence, VM
lifecycle and CPU/memory request validation, boot-order validation, network
address and bridge checks, storage-volume commands, repository URL validation,
SUSE subscription secret handling, account safety, host-group deletion,
operation queue limits, stale inventory refresh across three hosts including a
partial connectivity failure, backup destination access, custom S3 endpoint
allowlisting, secret redaction, host deletion, and SQLite schema migration.
Remote SSH/libvirt/S3 effects are mocked at their command boundaries. GitHub
Actions runs the suite for pull requests and pushes to `main`.

## What this suite does not prove

Mocked SSH tests verify the API contract and permission decisions; they do not
prove that a real SUSE host has the expected packages, sudo policy, libvirt
configuration, network manager, or HA add-on. Destructive or host-mutating
scenarios still need a disposable lab host and explicit test data. Add those as
separate integration tests rather than pointing automated tests at a production
cluster or the user's imported hosts.

## Next test layers

1. Add focused parser tests for SUSEConnect and libvirt XML plus broader error
   sanitization cases.
2. Add remaining route tests for VM device and snapshot operations, repository
   and account changes, backup upload/download and operation ownership.
3. Add browser-based Vue component tests for form validation, loading/error
   states, localization and role-based visibility.
4. Add opt-in integration tests through the Rancher deployment against a
   disposable SLES/KVM VM, with explicit inventory fixtures and cleanup
   verification. Do not use the developer workstation as a KVM test host.
