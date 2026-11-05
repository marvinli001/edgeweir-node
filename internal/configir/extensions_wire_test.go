package configir

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Same synthetic vectors as edgeweir/packages/config-compiler/test/fixtures/extension_wire_vectors.json.
// They cover field encoding independently of package signatures and IR validation.
func TestExtensionWireVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/extension_wire_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name         string          `json:"name"`
		Extension    json.RawMessage `json:"extension"`
		CanonicalHex string          `json:"canonical_hex"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(v.CanonicalHex)
			if err != nil {
				t.Fatal(err)
			}
			ext := &nodev1.Extension{}
			if err := protojson.Unmarshal(v.Extension, ext); err != nil {
				t.Fatal(err)
			}
			assertExtensionWire(t, ext, wire)
			if ext.Scope == "" && len(ext.Listeners) == 0 {
				ext.Listeners = []*nodev1.ExtensionListener{}
				assertExtensionWire(t, ext, wire)
			}
			var input struct {
				Listeners []struct {
					MaxBody *uint32 `json:"maxBody"`
				} `json:"listeners"`
			}
			if err := json.Unmarshal(v.Extension, &input); err != nil {
				t.Fatal(err)
			}
			for i, listener := range ext.Listeners {
				want := input.Listeners[i].MaxBody
				if (listener.MaxBody == nil) != (want == nil) || (want != nil && listener.GetMaxBody() != *want) {
					t.Fatalf("listener %d: max_body presence/value differs from JSON", i)
				}
			}
			wrappedJSON := append(append([]byte(`{"extensions":[`), v.Extension...), ']', '}')
			// Field 60, wire type 2: (60 << 3) | 2 = 482 = e2 03.
			wrappedWire := protowire.AppendBytes([]byte{0xe2, 0x03}, wire)
			for _, msg := range []proto.Message{&nodev1.NodeConfig{}, &nodev1.NodeConfigDiff{}} {
				t.Run(string(proto.MessageName(msg)), func(t *testing.T) {
					if err := protojson.Unmarshal(wrappedJSON, msg); err != nil {
						t.Fatal(err)
					}
					assertExtensionWire(t, msg, wrappedWire)
				})
			}
		})
	}
}

func assertExtensionWire(t *testing.T, msg proto.Message, want []byte) {
	t.Helper()
	got, err := (proto.MarshalOptions{Deterministic: true}).Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, want %x", got, want)
	}
	decoded := msg.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(want, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(decoded, msg) {
		t.Fatalf("decoded %v, want %v", decoded, msg)
	}
}
