// Package canonical implements JCS (RFC 8785) canonical JSON encoding.
// Only the subset needed for signed receipts is supported: objects with
// string keys, arrays, strings, booleans, nil, and numbers (int64, float64,
// json.Number). Object keys sort lexicographically; strings escape per RFC
// 8785; non-ASCII is emitted as UTF-8.
package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// Marshal returns the JCS canonical form of v.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeJSONString(buf, t)
	case int:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(t, 10))
	case float64:
		buf.WriteString(formatNumber(t))
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			// Integer-looking numbers pass through verbatim.
			buf.WriteString(t.String())
			return nil
		}
		buf.WriteString(formatNumber(f))
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// Fall back to encoding/json for structs and other named types,
		// then re-canonicalize so key order is still deterministic.
		raw, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("canonical: unsupported type %T: %w", v, err)
		}
		var decoded any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err != nil {
			return err
		}
		return encode(buf, decoded)
	}
	return nil
}

// formatNumber renders a float64 the way ECMAScript Number::toString does
// for the values we emit (integers and short decimals). Go's shortest
// representation matches for these; whole floats print without a fraction.
func formatNumber(f float64) string {
	if f == float64(int64(f)) && f >= -1e15 && f <= 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// writeJSONString writes s as a JSON string with RFC 8785 escaping.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
