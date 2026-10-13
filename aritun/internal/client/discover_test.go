package client

import "testing"

func TestNormalizeRespectsExplicitExclude(t *testing.T) {
	// A caller that wants 3456 and 10809 but has excluded 10809 (say, it is the
	// proxy we dial through) must get only 3456.
	opts := DiscoverOptions{
		Exclude:          map[int]bool{10809: true},
		ExcludeSystem:    true,
		ExcludeEphemeral: true,
	}
	got := normalize([]int{3456, 10809}, opts)
	if len(got) != 1 || got[0] != 3456 {
		t.Fatalf("expected [3456], got %v", got)
	}
}

func TestNormalizeDropsEphemeralOnlyDuringDiscovery(t *testing.T) {
	discover := DiscoverOptions{ExcludeSystem: true, ExcludeEphemeral: true}
	got := normalize([]int{3000, 22, 49664, 51020}, discover)
	if len(got) != 2 || got[0] != 22 || got[1] != 3000 {
		t.Fatalf("discovery should keep [22 3000], got %v", got)
	}

	// An explicit --ports list is a deliberate choice, so high ports stay.
	explicit := DiscoverOptions{ExcludeSystem: true, ExcludeEphemeral: false}
	got = normalize([]int{3000, 51020}, explicit)
	if len(got) != 2 {
		t.Fatalf("explicit list should keep high ports, got %v", got)
	}
}

func TestNormalizeDropsWindowsServicePorts(t *testing.T) {
	opts := DiscoverOptions{ExcludeSystem: true, ExcludeEphemeral: true}
	got := normalize([]int{135, 139, 445, 5357, 7680, 3000}, opts)
	if len(got) != 1 || got[0] != 3000 {
		t.Fatalf("expected only [3000], got %v", got)
	}
}
