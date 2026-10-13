package fakeconsole

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// SetChannel sets the node channel address heartbeats and probe rounds hand
// out (nil: none, like an older console).
func (c *Console) SetChannel(a *nodev1.ChannelAddress) {
	c.mu.Lock()
	c.channel = proto.CloneOf(a)
	c.mu.Unlock()
}

// DisableCheck makes CheckChannel and CheckProbeChannel answer
// Unimplemented, like a console before channel-follow-v1.
func (c *Console) DisableCheck(on bool) {
	c.mu.Lock()
	c.noCheck = on
	c.mu.Unlock()
}

// ChannelChecks returns the callers of CheckChannel and CheckProbeChannel.
func (c *Console) ChannelChecks() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.channelChecks...)
}

// CheckChannel implements NodeService.
func (c *Console) CheckChannel(ctx context.Context, _ *connect.Request[nodev1.CheckChannelRequest]) (*connect.Response[nodev1.CheckChannelResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.noCheck {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("CheckChannel is not implemented"))
	}
	c.channelChecks = append(c.channelChecks, c.opts.NodeID)
	return connect.NewResponse(&nodev1.CheckChannelResponse{NodeId: c.opts.NodeID, Channel: proto.CloneOf(c.channel)}), nil
}

// CheckProbeChannel implements ProbeService.
func (c *Console) CheckProbeChannel(ctx context.Context, _ *connect.Request[nodev1.CheckProbeChannelRequest]) (*connect.Response[nodev1.CheckProbeChannelResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.noCheck {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("CheckProbeChannel is not implemented"))
	}
	who := caller(ctx)
	c.channelChecks = append(c.channelChecks, who)
	return connect.NewResponse(&nodev1.CheckProbeChannelResponse{ProbeId: who, Channel: proto.CloneOf(c.channel)}), nil
}

// RejectNode makes every NodeService call but Enroll answer
// Unauthenticated, like the console for a deleted node.
func (c *Console) RejectNode(on bool) {
	c.mu.Lock()
	c.rejectNode = on
	c.mu.Unlock()
}
