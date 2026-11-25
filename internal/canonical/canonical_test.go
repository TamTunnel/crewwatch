package canonical

import (
	"testing"
)

func TestMarshalKeyOrder(t *testing.T) {
	got, err := Marshal(map[string]any{"b": 1, "a": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"b":1}` {
		t.Fatalf("got %s", got)
	}
}

func TestMarshalNestedAndEscapes(t *testing.T) {
	got, err := Marshal(map[string]any{
		"z": []any{"x\ny", true, nil, 1.5},
		"a": "café",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"café","z":["x\ny",true,null,1.5]}`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestMarshalFloatWhole(t *testing.T) {
	got, err := Marshal(map[string]any{"n": float64(42)})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"n":42}` {
		t.Fatalf("got %s", got)
	}
}
