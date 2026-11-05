package fakeconsole

import (
	"bytes"
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func (c *Console) SetExtensionPackage(digest string, archive []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.extensionPackages == nil {
		c.extensionPackages = map[string][]byte{}
	}
	c.extensionPackages[digest] = bytes.Clone(archive)
}

func (c *Console) SetExtensionSecret(secret *nodev1.ExtensionSecret) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.extensionSecrets == nil {
		c.extensionSecrets = map[string]*nodev1.ExtensionSecret{}
	}
	c.extensionSecrets[secret.GetId()] = proto.CloneOf(secret)
}

func (c *Console) SetExtensionPackageError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.extensionPackageError = err
}

func (c *Console) GetExtensionPackage(_ context.Context, req *connect.Request[nodev1.GetExtensionPackageRequest]) (*connect.Response[nodev1.GetExtensionPackageResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.extensionPackageError != nil {
		return nil, c.extensionPackageError
	}
	archive, ok := c.extensionPackages[req.Msg.GetSha256()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such extension package"))
	}
	offset := req.Msg.GetOffset()
	if offset >= uint64(len(archive)) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid package offset"))
	}
	end := min(offset+(4<<20), uint64(len(archive)))
	return connect.NewResponse(&nodev1.GetExtensionPackageResponse{Package: bytes.Clone(archive[offset:end]), Total: uint64(len(archive))}), nil
}

func (c *Console) GetExtensionSecrets(_ context.Context, req *connect.Request[nodev1.GetExtensionSecretsRequest]) (*connect.Response[nodev1.GetExtensionSecretsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := &nodev1.GetExtensionSecretsResponse{}
	for _, id := range req.Msg.GetIds() {
		if secret := c.extensionSecrets[id]; secret != nil {
			out.Secrets = append(out.Secrets, proto.CloneOf(secret))
		}
	}
	return connect.NewResponse(out), nil
}
