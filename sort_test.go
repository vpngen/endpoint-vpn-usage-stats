package main

import (
	"strings"
	"testing"
)

const text = `1 f1 s1
3 f2 s2
4 f2 s2
3 f1 s1
4 f1 s1
2 f1 s1`

func TestSort(t *testing.T) {
	t.Log(sortFirstField(strings.NewReader(text)))
}

func TestSortUnique(t *testing.T) {
	t.Log(sortFirstFieldUnique(strings.NewReader(text)))
}
