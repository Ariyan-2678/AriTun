package client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Friendly subdomain generator, in the spirit of ngrok's random hostnames.
var adjectives = []string{
	"swift", "quiet", "brave", "lucky", "clever", "amber", "crimson",
	"golden", "silver", "cobalt", "ivory", "jade", "onyx", "rusty",
	"gentle", "mighty", "nimble", "polite", "radiant", "steady",
}

var animals = []string{
	"fox", "otter", "heron", "lynx", "wolf", "falcon", "badger",
	"cobra", "finch", "gecko", "moose", "panda", "quail", "raven",
	"shark", "tiger", "viper", "whale", "yak", "zebra",
}

// RandomSubdomain returns something like "swift-fox-42".
func RandomSubdomain() string {
	a := adjectives[randInt(len(adjectives))]
	b := animals[randInt(len(animals))]
	n := randInt(900) + 100
	return fmt.Sprintf("%s-%s-%d", a, b, n)
}

func randInt(n int) int {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}
