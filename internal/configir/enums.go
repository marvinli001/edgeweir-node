package configir

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// validateEnums rejects semantics this agent cannot implement. Protobuf keeps
// unknown enum numbers, so silently falling through a switch can downgrade TLS
// or turn a future cache policy into a permissive default.
func validateEnums(message protoreflect.Message) error {
	var invalid error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		check := func(v protoreflect.Value) error {
			switch field.Kind() {
			case protoreflect.EnumKind:
				if field.Enum().Values().ByNumber(v.Enum()) == nil {
					return fmt.Errorf("%w: unsupported %s value %d", ErrRejected, field.FullName(), v.Enum())
				}
			case protoreflect.MessageKind, protoreflect.GroupKind:
				return validateEnums(v.Message())
			}
			return nil
		}
		if field.IsList() {
			for i := 0; i < value.List().Len(); i++ {
				if invalid = check(value.List().Get(i)); invalid != nil {
					return false
				}
			}
		} else if !field.IsMap() {
			invalid = check(value)
		}
		return invalid == nil
	})
	return invalid
}
