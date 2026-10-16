package scan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/ANetResearch/ANetCore/wire"
)

var rawJSON = reflect.TypeFor[json.RawMessage]()

// jsonMembers returns the JSON members encoding/json writes for struct type t, by name.
func jsonMembers(t reflect.Type) map[string]reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := map[string]reflect.Type{}
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range jsonMembers(ft) {
					if _, ok := out[k]; !ok {
						out[k] = v
					}
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// jsonKindOK says whether a Go member type can carry a registered JSON member type.
func jsonKindOK(t reflect.Type, want string) bool {
	if t == rawJSON {
		return true
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	k := t.Kind()
	switch want {
	case "any":
		return true
	case "string", "b64url", "hex", "enum":
		return k == reflect.String
	case "base64":
		return k == reflect.String || (k == reflect.Slice && t.Elem().Kind() == reflect.Uint8)
	case "uint", "int":
		// JSON has one number type; the sign is a value check, not a type
		return k >= reflect.Int && k <= reflect.Uint64
	case "bool":
		return k == reflect.Bool
	case "object":
		return k == reflect.Struct || k == reflect.Map || k == reflect.Interface
	case "array":
		return (k == reflect.Slice || k == reflect.Array) && t.Elem().Kind() != reflect.Uint8 || k == reflect.Interface
	}
	return false
}

// JSONFields compares the JSON members of Go type t with a registered body (CORE-S5) and returns
// one line per difference. A full body must match member for member; a partial one lists only
// the members wire 3 adds or changes, which must all be there. Registered sub-members are
// compared one level down when the Go member is a struct, a pointer to one or a slice of them.
func JSONFields(t reflect.Type, b *wire.Body) []string {
	if b == nil {
		return []string{"no registered body"}
	}
	if b.Raw != "" {
		return []string{"the registered body is not JSON (" + b.Raw + ")"}
	}
	if len(b.Alt) > 0 {
		return []string{"the registered body has alternatives: compare against one of them"}
	}
	return compareMembers("", t, b.Fields, !b.Partial)
}

func compareMembers(prefix string, t reflect.Type, fields []*wire.Field, exact bool) []string {
	var out []string
	have := jsonMembers(t)
	want := map[string]bool{}
	for _, f := range fields {
		want[f.Name] = true
		gt, ok := have[f.Name]
		if !ok {
			out = append(out, fmt.Sprintf("member %s%s is registered but %s has no field for it", prefix, f.Name, t))
			continue
		}
		if !jsonKindOK(gt, f.Type) {
			out = append(out, fmt.Sprintf("member %s%s is registered as %s; the Go field is %s", prefix, f.Name, f.Type, gt))
			continue
		}
		if len(f.Fields) > 0 {
			et := gt
			for et.Kind() == reflect.Pointer || et.Kind() == reflect.Slice || et.Kind() == reflect.Array {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				out = append(out, compareMembers(prefix+f.Name+".", et, f.Fields, exact)...)
			}
		}
	}
	if exact {
		var extra []string
		for name := range have {
			if !want[name] {
				extra = append(extra, prefix+name)
			}
		}
		sort.Strings(extra)
		for _, name := range extra {
			out = append(out, fmt.Sprintf("member %s of %s is not registered", name, t))
		}
	}
	return out
}

// Alt returns the alternative of b whose When contains when, or nil.
func Alt(b *wire.Body, when string) *wire.Body {
	if b == nil {
		return nil
	}
	for _, a := range b.Alt {
		if strings.Contains(a.When, when) {
			return a
		}
	}
	return nil
}
