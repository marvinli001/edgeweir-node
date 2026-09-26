module github.com/marvinli001/edgeweir-node

go 1.27.1

require (
	connectrpc.com/connect v1.21.0
	golang.org/x/crypto v0.50.0
	google.golang.org/protobuf v1.36.12
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
