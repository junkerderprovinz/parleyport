package notify_test

import "strings"

func ptr[T any](v T) *T { return &v }

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
