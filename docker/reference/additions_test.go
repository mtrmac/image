package reference

import (
	"regexp"
	"testing"
)

func TestExplicitRegistryRegexp(t *testing.T) {
	cases := []regexpMatch{
		// These are the cases from TestDomainRegexp, except the "a" one has been changed to match: false.
		{
			input: "test.com",
			match: true,
		},
		{
			input: "test.com:10304",
			match: true,
		},
		{
			input: "test.com:http",
			match: false,
		},
		{
			input: "localhost",
			match: true,
		},
		{
			input: "localhost:8080",
			match: true,
		},
		{
			input: "a",
			match: false,
		},
		{
			input: "a.b",
			match: true,
		},
		{
			input: "ab.cd.com",
			match: true,
		},
		{
			input: "a-b.com",
			match: true,
		},
		{
			input: "-ab.com",
			match: false,
		},
		{
			input: "ab-.com",
			match: false,
		},
		{
			input: "ab.c-om",
			match: true,
		},
		{
			input: "ab.-com",
			match: false,
		},
		{
			input: "ab.com-",
			match: false,
		},
		{
			input: "0101.com",
			match: true, // TODO(dmcgowan): valid if this should be allowed
		},
		{
			input: "001a.com",
			match: true,
		},
		{
			input: "b.gbc.io:443",
			match: true,
		},
		{
			input: "b.gbc.io",
			match: true,
		},
		{
			input: "xn--n3h.com", // ☃.com in punycode
			match: true,
		},
		{
			input: "Asdf.com", // uppercase character
			match: true,
		},
		// New test cases
		{
			input: "a:443",
			match: true,
		},
		{
			input: "prefixlocalhost",
			match: false,
		},
		{
			input: "localhostsuffix",
			match: false,
		},
	}
	r := regexp.MustCompile(`^` + ExplicitRegistryRegexp.String() + `$`)
	for i := range cases {
		checkRegexp(t, r, cases[i])
	}
}
