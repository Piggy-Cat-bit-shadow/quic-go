package slices

import (
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

type Ordered = constraints.Ordered

// Sort sorts a slice of any ordered type in ascending order.
// When sorting floating-point numbers, NaNs are ordered before other values.
func Sort[S ~[]E, E Ordered](x S) {
	slices.Sort(x)
}

// SortFunc sorts the slice x in ascending order as determined by the cmp
// function. This sort is not guaranteed to be stable.
// cmp(a, b) should return a negative number when a < b, a positive number when
// a > b and zero when a == b or when a is not comparable to b in the sense
// of the formal definition of Strict Weak Ordering.
//
// SortFunc requires that cmp is a strict weak ordering.
// See https://en.wikipedia.org/wiki/Weak_ordering#Strict_weak_orderings.
// To indicate 'uncomparable', return 0 from the function.
func SortFunc[S ~[]E, E any](x S, cmp func(a, b E) int) {
	slices.SortFunc(x, cmp)
}

// SortStableFunc sorts the slice x while keeping the original order of equal
// elements, using cmp to compare elements in the same way as [SortFunc].
func SortStableFunc[S ~[]E, E any](x S, cmp func(a, b E) int) {
	slices.SortStableFunc(x, cmp)
}

// IsSorted reports whether x is sorted in ascending order.
func IsSorted[S ~[]E, E Ordered](x S) bool {
	return slices.IsSorted(x)
}

// IsSortedFunc reports whether x is sorted in ascending order, with cmp as the
// comparison function as defined by [SortFunc].
func IsSortedFunc[S ~[]E, E any](x S, cmp func(a, b E) int) bool {
	return slices.IsSortedFunc(x, cmp)
}
