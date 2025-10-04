// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package maps

// All returns an iterator over key-value pairs from m.
// The iteration order is not specified and is not guaranteed
// to be the same from one call to the next.
func All[Map ~map[K]V, K comparable, V any](m Map) func(yield func(K, V) bool) {
	return func(yield func(K, V) bool) {
		for k, v := range m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// Keys returns an iterator over keys in m.
// The iteration order is not specified and is not guaranteed
// to be the same from one call to the next.
func Keys[Map ~map[K]V, K comparable, V any](m Map) func(yield func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// Values returns an iterator over values in m.
// The iteration order is not specified and is not guaranteed
// to be the same from one call to the next.
func Values[Map ~map[K]V, K comparable, V any](m Map) func(yield func(V) bool) {
	return func(yield func(V) bool) {
		for _, v := range m {
			if !yield(v) {
				return
			}
		}
	}
}

// Insert adds the key-value pairs from seq to m.
// If a key in seq already exists in m, its value will be overwritten.
func Insert[Map ~map[K]V, K comparable, V any](m Map, seq func(yield func(K, V) bool)) {
	seq(func(k K, v V) bool {
		m[k] = v
		return true
	})
}

// Collect collects key-value pairs from seq into a new map
// and returns it.
func Collect[K comparable, V any](seq func(yield func(K, V) bool)) map[K]V {
	m := make(map[K]V)
	Insert(m, seq)
	return m
}
