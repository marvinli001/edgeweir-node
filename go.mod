module github.com/marvinli001/edgeweir-node

go 1.27.1

require (
	connectrpc.com/connect v1.21.0
	github.com/coder/websocket v1.8.15
	github.com/maxmind/mmdbwriter v1.2.0
	github.com/oschwald/maxminddb-golang/v2 v2.6.0
	golang.org/x/crypto v0.50.0
	google.golang.org/protobuf v1.36.12
)

require (
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/sys v0.47.0 // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
