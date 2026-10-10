module github.com/marvinli001/edgeweir-node

go 1.27.1

require (
	connectrpc.com/connect v1.21.0
	github.com/coder/websocket v1.8.15
	github.com/gen2brain/avif v0.6.0
	github.com/gen2brain/webp v0.6.4
	github.com/maxmind/mmdbwriter v1.2.0
	github.com/oschwald/maxminddb-golang/v2 v2.6.0
	golang.org/x/crypto v0.50.0
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/ebitengine/purego v0.10.1 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
