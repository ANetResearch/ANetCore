package coredet

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// ErrNullOrUndefined is what a NullError matches with errors.Is.
var ErrNullOrUndefined = errors.New("coredet: CBOR null or undefined where a value must be")

// NullError is UnmarshalStrict's refusal of a CBOR undefined (simple value 23) anywhere in its
// input, or of a CBOR null decoded into a target that cannot be absent: anything but a pointer, an
// interface or a cbor.RawMessage (CORE-E4, revision 7). The decoder takes both into the zero value
// without a word, so `81 f7` decodes into a list of one empty entry; neither re-encodes to the
// bytes that were received, and no registered object has a field that may be null.
type NullError struct {
	// Undefined is true for a CBOR undefined, false for a null.
	Undefined bool
	// Path is where the item is: ".<key>" for a map member, "[<i>]" for an array element, ""
	// for the whole input.
	Path string
	// Into is the Go type the null would have decoded into; "" for an undefined.
	Into string
}

func (e *NullError) Error() string {
	at := e.Path
	if at == "" {
		at = "the top level"
	}
	if e.Undefined {
		return "coredet: CBOR undefined at " + at + ": no canonical encoding carries it"
	}
	return "coredet: CBOR null at " + at + " would decode into " + e.Into + " as its zero value; " +
		"only a pointer, an interface or a raw message may be null"
}

// Is makes errors.Is(err, ErrNullOrUndefined) hold for a NullError.
func (e *NullError) Is(target error) bool { return target == ErrNullOrUndefined }

// refuseNulls returns a NullError for the first CBOR undefined in b, or the first null in b whose
// target in t (the type b decoded into) cannot be absent; nil when there is none. b has already
// decoded into t (UnmarshalStrict calls it after the decoder succeeded), so it is well formed and
// its shape matches t; the walk still checks every bound and returns an error rather than read
// past the end.
func refuseNulls(b []byte, t reflect.Type) error {
	// Neither byte anywhere: no null or undefined item (a byte inside a string or a number is not
	// one, and only costs the walk).
	if bytes.IndexByte(b, 0xf6) < 0 && bytes.IndexByte(b, 0xf7) < 0 {
		return nil
	}
	w := nullWalk{b: b}
	if err := w.item(target{t: t}, 0); err != nil {
		return err
	}
	if w.off != len(b) {
		return fmt.Errorf("coredet: %d bytes after the data item", len(b)-w.off)
	}
	return nil
}

// target is what a data item decodes into. t nil is an item the decoder keeps without a type to
// hold it to (under an interface, a raw message or a type with its own UnmarshalCBOR): a null in
// it is not refused. unknown is an item whose target the walk could not name; a null in it is
// refused, the safe side.
type target struct {
	t       reflect.Type
	unknown bool
}

var (
	opaque        = target{}
	unknownTarget = target{unknown: true}

	typeRawMessage  = reflect.TypeFor[cbor.RawMessage]()
	typeUnmarshaler = reflect.TypeFor[cbor.Unmarshaler]()
)

// maxNullWalkDepth bounds the walk's recursion. The decoder's own limit is 32 nested levels, and
// the walk only sees what the decoder took.
const maxNullWalkDepth = 64

type nullWalk struct {
	b    []byte
	off  int
	path []string
}

func (w *nullWalk) errAt(undefined bool, into reflect.Type) error {
	e := &NullError{Undefined: undefined, Path: strings.Join(w.path, "")}
	if !undefined {
		if into == nil {
			e.Into = "a value of unknown type"
		} else {
			e.Into = into.String()
		}
	}
	return e
}

var errNullWalkShort = errors.New("coredet: data item cut short")

// head reads the initial byte and argument of the item at w.off.
func (w *nullWalk) head() (major byte, ai byte, arg uint64, err error) {
	if w.off >= len(w.b) {
		return 0, 0, 0, errNullWalkShort
	}
	ib := w.b[w.off]
	w.off++
	major, ai = ib>>5, ib&0x1f
	n := 0
	switch {
	case ai < 24:
		return major, ai, uint64(ai), nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	case ai == 31:
		return major, ai, 0, nil // indefinite length, or break
	default:
		return 0, 0, 0, fmt.Errorf("coredet: reserved additional information %d", ai)
	}
	if len(w.b)-w.off < n {
		return 0, 0, 0, errNullWalkShort
	}
	for _, c := range w.b[w.off : w.off+n] {
		arg = arg<<8 | uint64(c)
	}
	w.off += n
	return major, ai, arg, nil
}

// isBreak consumes a break (0xff) at w.off and reports whether there was one.
func (w *nullWalk) isBreak() (bool, error) {
	if w.off >= len(w.b) {
		return false, errNullWalkShort
	}
	if w.b[w.off] == 0xff {
		w.off++
		return true, nil
	}
	return false, nil
}

// nullable reports whether a null may decode into t: a pointer, an interface or a raw message,
// all of which the decoder sets to nil.
func nullable(t reflect.Type) bool {
	k := t.Kind()
	return k == reflect.Pointer || k == reflect.Interface || t == typeRawMessage
}

// item walks one data item against its target.
func (w *nullWalk) item(tg target, depth int) error {
	if depth > maxNullWalkDepth {
		return errors.New("coredet: data items nested too deep")
	}
	if w.off >= len(w.b) {
		return errNullWalkShort
	}
	switch w.b[w.off] {
	case 0xf7:
		return w.errAt(true, nil)
	case 0xf6:
		switch {
		case tg.unknown:
			return w.errAt(false, nil)
		case tg.t != nil && !nullable(tg.t):
			return w.errAt(false, tg.t)
		}
		w.off++
		return nil
	}
	tg = elemTarget(tg)
	major, ai, arg, err := w.head()
	if err != nil {
		return err
	}
	switch major {
	case 0, 1: // integers
		return nil
	case 2, 3: // byte and text strings
		if ai == 31 {
			for {
				brk, err := w.isBreak()
				if err != nil || brk {
					return err
				}
				cm, _, n, err := w.head()
				if err != nil {
					return err
				}
				if cm != major {
					return errors.New("coredet: a string chunk of another type")
				}
				if err := w.skip(n); err != nil {
					return err
				}
			}
		}
		return w.skip(arg)
	case 4: // array
		return w.array(tg, ai == 31, arg, depth)
	case 5: // map
		return w.mapItem(tg, ai == 31, arg, depth)
	case 6: // tag: the strict decoder forbids them; walk the content against the same target
		return w.item(tg, depth+1)
	default: // 7: simple values and floats; null and undefined were handled above
		return nil
	}
}

func (w *nullWalk) skip(n uint64) error {
	if uint64(len(w.b)-w.off) < n {
		return errNullWalkShort
	}
	w.off += int(n)
	return nil
}

// elemTarget is the target an item that is not null decodes into: through the pointers, and
// opaque where the decoder stops holding it to a type.
func elemTarget(tg target) target {
	if tg.t == nil {
		return tg
	}
	t := tg.t
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Interface || t == typeRawMessage || reflect.PointerTo(t).Implements(typeUnmarshaler) {
		// A type with its own UnmarshalCBOR decides what it takes; every one in the suite decodes
		// strictly itself, which brings it back here.
		return opaque
	}
	return target{t: t}
}

func (w *nullWalk) array(tg target, indefinite bool, n uint64, depth int) error {
	var elem func(i int) target
	switch {
	case tg.unknown:
		elem = func(int) target { return unknownTarget }
	case tg.t == nil:
		elem = func(int) target { return opaque }
	case tg.t.Kind() == reflect.Slice || tg.t.Kind() == reflect.Array:
		et := target{t: tg.t.Elem()}
		elem = func(int) target { return et }
	case tg.t.Kind() == reflect.Struct:
		si := structInfoOf(tg.t)
		elem = func(i int) target {
			if si.toArray && i < len(si.array) {
				return target{t: si.array[i]}
			}
			return unknownTarget
		}
	default:
		elem = func(int) target { return unknownTarget }
	}
	for i := 0; ; i++ {
		if indefinite {
			brk, err := w.isBreak()
			if err != nil {
				return err
			}
			if brk {
				return nil
			}
		} else if uint64(i) >= n {
			return nil
		}
		w.path = append(w.path, "["+strconv.Itoa(i)+"]")
		if err := w.item(elem(i), depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
}

func (w *nullWalk) mapItem(tg target, indefinite bool, n uint64, depth int) error {
	var si *structInfo
	if tg.t != nil && tg.t.Kind() == reflect.Struct {
		si = structInfoOf(tg.t)
	}
	for i := 0; ; i++ {
		if indefinite {
			brk, err := w.isBreak()
			if err != nil {
				return err
			}
			if brk {
				return nil
			}
		} else if uint64(i) >= n {
			return nil
		}
		keyStart := w.off
		var keyTg, valTg target
		switch {
		case tg.unknown:
			keyTg, valTg = unknownTarget, unknownTarget
		case tg.t == nil:
			keyTg, valTg = opaque, opaque
		case tg.t.Kind() == reflect.Map:
			keyTg, valTg = target{t: tg.t.Key()}, target{t: tg.t.Elem()}
		case si != nil && !si.toArray:
			keyTg, valTg = opaque, unknownTarget
		default:
			keyTg, valTg = unknownTarget, unknownTarget
		}
		w.path = append(w.path, ".key")
		if err := w.item(keyTg, depth+1); err != nil {
			return err
		}
		w.path[len(w.path)-1] = "." + keyText(w.b[keyStart:w.off])
		if si != nil && !si.toArray {
			if ft, ok := si.field(w.b[keyStart:w.off]); ok {
				valTg = target{t: ft}
			}
		}
		if err := w.item(valTg, depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
}

// keyText is a map key for a NullError's path: an integer or a text string as written, any other
// key as "?".
func keyText(k []byte) string {
	w := nullWalk{b: k}
	major, ai, arg, err := w.head()
	switch {
	case err != nil || ai == 31:
		return "?"
	case major == 0:
		return strconv.FormatUint(arg, 10)
	case major == 1:
		return "-1-" + strconv.FormatUint(arg, 10)
	case major == 3 && w.off+int(arg) == len(k):
		return strconv.Quote(string(k[w.off:]))
	}
	return "?"
}

// structInfo is how the decoder matches a struct's fields (fxamacker/cbor's rules: the cbor tag,
// else the json tag, else the field name; keyasint; toarray; embedded structs promoted as
// encoding/json promotes them), reduced to the field types.
type structInfo struct {
	toArray bool
	array   []reflect.Type         // toarray: the field types in order
	byInt   map[int64]reflect.Type // keyasint fields
	byName  map[string]reflect.Type
	names   []nameType // the fields matched by name, in order, for the case-insensitive fallback
}

type nameType struct {
	name string
	t    reflect.Type
}

// field is the type of the field a map key (its encoding) decodes into.
func (s *structInfo) field(key []byte) (reflect.Type, bool) {
	w := nullWalk{b: key}
	major, ai, arg, err := w.head()
	if err != nil || ai == 31 {
		return nil, false
	}
	switch major {
	case 0:
		if arg > 1<<63-1 {
			return nil, false
		}
		t, ok := s.byInt[int64(arg)]
		return t, ok
	case 1:
		if arg > 1<<63-1 {
			return nil, false
		}
		t, ok := s.byInt[-1-int64(arg)]
		return t, ok
	case 3:
		if w.off+int(arg) != len(key) {
			return nil, false
		}
		name := string(key[w.off:])
		if t, ok := s.byName[name]; ok {
			return t, true
		}
		for _, f := range s.names {
			if len(f.name) == len(name) && strings.EqualFold(f.name, name) {
				return f.t, true
			}
		}
	}
	return nil, false
}

var structInfos sync.Map // reflect.Type -> *structInfo

func structInfoOf(t reflect.Type) *structInfo {
	if v, ok := structInfos.Load(t); ok {
		return v.(*structInfo)
	}
	s := buildStructInfo(t)
	v, _ := structInfos.LoadOrStore(t, s)
	return v.(*structInfo)
}

// sfield is one candidate field while the struct's visible fields are worked out.
type sfield struct {
	name     string
	nameInt  int64
	idx      []int
	typ      reflect.Type
	keyAsInt bool
	tagged   bool
}

func buildStructInfo(t reflect.Type) *structInfo {
	var opts string
	if f, ok := t.FieldByName("_"); ok {
		if tag := f.Tag.Get("cbor"); tag != "-" {
			opts = tag
		}
	}
	flds, next := appendStructFields(t, nil, nil, nil)
	visited := map[reflect.Type]bool{t: true}
	for len(next) > 0 {
		cur := next
		next = nil
		for _, ty := range sortedTypes(cur) {
			idx := cur[ty]
			// Several embedded structs of one type at one level are all ignored, and one of a type
			// already seen higher up is too.
			if len(idx) > 1 || visited[ty] {
				continue
			}
			visited[ty] = true
			flds, next = appendStructFields(ty, idx[0], flds, next)
		}
	}
	for _, f := range flds {
		if f.keyAsInt {
			if n, err := strconv.Atoi(f.name); err == nil {
				f.nameInt = int64(n)
				f.name = strconv.Itoa(n)
			}
		}
	}
	// The visible fields: of the fields with one (name, keyasint), the least nested, and of those
	// a tagged one; when that leaves more than one, none.
	byKey := map[string][]*sfield{}
	var order []string
	for _, f := range flds {
		k := f.name + "\x00" + strconv.FormatBool(f.keyAsInt)
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], f)
	}
	var visible []*sfield
	for _, k := range order {
		if f := dominant(byKey[k]); f != nil {
			visible = append(visible, f)
		}
	}
	sortByIndex(visible)
	s := &structInfo{toArray: hasToArray(opts), byInt: map[int64]reflect.Type{}, byName: map[string]reflect.Type{}}
	for _, f := range visible {
		if s.toArray {
			s.array = append(s.array, f.typ)
			continue
		}
		if f.keyAsInt {
			s.byInt[f.nameInt] = f.typ
		} else {
			s.byName[f.name] = f.typ
			s.names = append(s.names, nameType{f.name, f.typ})
		}
	}
	return s
}

// dominant is the field that wins among fields of one (name, keyasint): the least nested, then
// the tagged one; nil when two tie.
func dominant(fs []*sfield) *sfield {
	best := []*sfield{}
	for _, f := range fs {
		switch {
		case len(best) == 0 || len(f.idx) < len(best[0].idx):
			best = []*sfield{f}
		case len(f.idx) == len(best[0].idx):
			best = append(best, f)
		}
	}
	if len(best) == 1 {
		return best[0]
	}
	var tagged []*sfield
	for _, f := range best {
		if f.tagged {
			tagged = append(tagged, f)
		}
	}
	if len(tagged) == 1 {
		return tagged[0]
	}
	return nil
}

func appendStructFields(t reflect.Type, idx []int, flds []*sfield, next map[reflect.Type][][]int) ([]*sfield, map[reflect.Type][][]int) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if !f.IsExported() && !(f.Anonymous && ft.Kind() == reflect.Struct) {
			continue
		}
		tag := f.Tag.Get("cbor")
		if tag == "" {
			tag = f.Tag.Get("json")
		}
		if tag == "-" {
			continue
		}
		tagged := tag != ""
		name, rest, _ := strings.Cut(tag, ",")
		keyAsInt := false
		for _, o := range strings.Split(rest, ",") {
			if o == "keyasint" {
				keyAsInt = true
			}
		}
		fidx := append(append([]int(nil), idx...), i)
		if !f.Anonymous || ft.Kind() != reflect.Struct || name != "" {
			if name == "" {
				name = f.Name
			}
			flds = append(flds, &sfield{name: name, idx: fidx, typ: f.Type, keyAsInt: keyAsInt, tagged: tagged})
			continue
		}
		if next == nil {
			next = map[reflect.Type][][]int{}
		}
		next[ft] = append(next[ft], fidx)
	}
	return flds, next
}

func hasToArray(opts string) bool {
	for _, o := range strings.Split(opts, ",")[1:] {
		if o == "toarray" {
			return true
		}
	}
	return false
}

// sortedTypes orders a level's embedded types by where they are, so that the walk is the same
// every time.
func sortedTypes(m map[reflect.Type][][]int) []reflect.Type {
	out := make([]reflect.Type, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && indexLess(m[out[j]][0], m[out[j-1]][0]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func sortByIndex(fs []*sfield) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && indexLess(fs[j].idx, fs[j-1].idx); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func indexLess(a, b []int) bool {
	for k := 0; k < len(a) && k < len(b); k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return len(a) < len(b)
}
