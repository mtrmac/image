package reference

import "regexp"

// NOTE: additions.go do not originate in docker/distribution/reference.
// They primarily exist to support the projectatomic/docker "(un)qualified reference" concept
// of references which do (not) explicitly specify a registry.

var (
	// ExplicitRegistryRegexp is a subset of DomainRegexp, which is recognized by
	// ParseNormalizedNamed as a registry (as opposed to a namespace in docker.io),
	// or by projectatomic/docker as a qualified regitry prefix.
	// WARNING: Do not use DomainRegexp for this purpose (it matches "ns" in "ns/busybox" == "docker.io/ns/busybox").
	// WARNING: Do not just match this against a start of a string, a '/' must follow
	// (otherwise "example.com" == "docker.io/library/example.com" would be misdetected).
	ExplicitRegistryRegexp = alternatives(
		// per splitDockerDomain, a domain must match contain either "."
		expression( // (and then Parse must accept it, i.e. it must be a subset of DomainRegexp)
			domainComponentRegexp,
			repeated(literal(`.`), domainComponentRegexp), // This is optional() in DomainRegexp
			optional(literal(`:`), match(`[0-9]+`))),
		// or ":" (it may contain both, which is fine),
		expression( // (and then Parse must accept it, i.e. it must be a subset of DomainRegexp)
			domainComponentRegexp,
			optional(repeated(literal(`.`), domainComponentRegexp)),
			literal(`:`), match(`[0-9]+`)), // This is optional() in DomainRegexp
		// or be "localhost"
		literal(`localhost`))

	// NameWithExplicitRegistryRegexp is an variant of NameRegexp which _requires_
	// domain to be present, and recognized by ParseNormalizedNamed as a registry (as opposed
	// to a namespace in docker.io).
	// WARNING: Do not use the first capturing group in NameRegexp for this purpose
	// FIXME: Is this what we need?
	NameWithExplicitRegistryRegexp = expression(
		ExplicitRegistryRegexp,
		nameComponentRegexp,
		optional(repeated(literal(`/`), nameComponentRegexp)))

	// ReferenceWithExplicitRegistryRegexp is...
	// FIXME: Is this what we need?
	ReferenceWithExplicitRegistryRegexp = anchored(capture(NameWithExplicitRegistryRegexp),
		optional(literal(":"), capture(TagRegexp)),
		optional(literal("@"), capture(DigestRegexp)))
)

// alternatives defines a full expression matching either of the supplied expressions.
func alternatives(res ...*regexp.Regexp) *regexp.Regexp {
	s := ""
	for _, re := range res {
		if s != "" {
			s += "|"
		}
		s += re.String()
	}
	return match(`(?:` + s + `)`)
}
