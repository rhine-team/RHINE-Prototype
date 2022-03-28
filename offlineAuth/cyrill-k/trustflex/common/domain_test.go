package common

import (
	"fmt"
	"testing"
)

func TestIsViableDomain(t *testing.T) {
	tests := map[string]bool{
		"01010": false,
		"abc":   true,
		"A0c":   true,
		"A0c-":  false,
		"-A0c":  false,
		"A-0c":  true,
		"o123456701234567012345670123456701234567012345670123456701234567": false,
		"o12345670123456701234567012345670123456701234567012345670123456":  true,
		"":     false,
		"a":    true,
		"0--0": true,
	}
	for label, result := range tests {
		if IsViableDomain(label) != result {
			t.Errorf("IsViableDomain(%s) != %+v", label, result)
		}
	}
}

func TestSplitE2LD(t *testing.T) {
	tests := map[string][]string{
		"a.b.com":     []string{"a", "b.com"},
		"a.b.invalid": []string{},
		"a.b.c.d.com": []string{"a", "b", "c", "d.com"},
		"a.ac.jp":     []string{"a.ac.jp"},
		"-.com":       []string{},
	}
	for domain, labels := range tests {
		x, err := SplitE2LD(domain)
		fmt.Println(err)
		if !StringSliceCompare(x, labels) {
			t.Errorf("SplitE2LD(%s) = %+v != %+v", domain, x, labels)
		}
	}
}


func TestSplitE2LD2(t *testing.T) {
	tests := map[string][]string{
		"a.b.com":     []string{"a", "b.com"},
		"a.b.invalid": []string{},
		"a.b.c.d.com": []string{"a", "b", "c", "d.com"},
		"a.ac.jp":     []string{"a.ac.jp"},
		"-.com":       []string{},
		"ethz.ch": nil,
		"ch":nil,
		"inf.ethz.ch": nil,

	}
	for domain, _ := range tests {
		x, err := SplitE2LD(domain)
		fmt.Println(x)
		fmt.Println(err)

	}
}
