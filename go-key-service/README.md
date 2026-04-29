# go-key-service

Go HTTP service for agent identity and Ed25519 key management.

## Layout

- `cmd/keyserver/` — entrypoint binary
- `internal/action/` — canonical action schema + encoding (shared with `sdk-python`)

## Run

```sh
go run ./cmd/keyserver
```

## Test

```sh
go test ./...
```
