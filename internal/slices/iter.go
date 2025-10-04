package slices

// All returns an iterator over index-value pairs in the slice
// in the usual order.
func All[Slice ~[]E, E any](s Slice) func(yield func(int, E) bool) {
	return func(yield func(int, E) bool) {
		for i, v := range s {
			if !yield(i, v) {
				return
			}
		}
	}
}

// Backward returns an iterator over index-value pairs in the slice,
// traversing it backward with descending indices.
func Backward[Slice ~[]E, E any](s Slice) func(yield func(int, E) bool) {
	return func(yield func(int, E) bool) {
		for i := len(s) - 1; i >= 0; i-- {
			if !yield(i, s[i]) {
				return
			}
		}
	}
}

// Values returns an iterator that yields the slice elements in order.
func Values[Slice ~[]E, E any](s Slice) func(yield func(E) bool) {
	return func(yield func(E) bool) {
		for _, v := range s {
			if !yield(v) {
				return
			}
		}
	}
}

// AppendSeq appends the values from seq to the slice and
// returns the extended slice.
// If seq is empty, the result preserves the nilness of s.
func AppendSeq[Slice ~[]E, E any](s Slice, seq func(yield func(E) bool)) Slice {
	seq(func(v E) bool {
		s = append(s, v)
		return true
	})
	return s
}

// Collect collects values from seq into a new slice and returns it.
// If seq is empty, the result is nil.
func Collect[E any](seq func(yield func(E) bool)) []E {
	return AppendSeq([]E(nil), seq)
}

// Sorted collects values from seq into a new slice, sorts the slice,
// and returns it.
// If seq is empty, the result is nil.
func Sorted[E Ordered](seq func(yield func(E) bool)) []E {
	s := Collect(seq)
	Sort(s)
	return s
}

// SortedFunc collects values from seq into a new slice, sorts the slice
// using the comparison function, and returns it.
// If seq is empty, the result is nil.
func SortedFunc[E any](seq func(yield func(E) bool), cmp func(E, E) int) []E {
	s := Collect(seq)
	SortFunc(s, cmp)
	return s
}
