// Policy evaluation for prSignedBy.

package signature

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
)

// verificationCache contains data cached in PolicyContext to speed up signature verification
// FIXME? Generalize this to be initialized when parsing the policy, instead of having specific fields in PolicyContext? Or is this cleaner?
type verificationCache struct {
	mech              SigningMechanism
	trustedIdentities []string
}

func verificationCacheFromData(data []byte) (verificationCache, error) {
	mech, trustedIdentities, err := NewEphemeralGPGSigningMechanism(data)
	if err != nil {
		return verificationCache{}, err
	}
	return verificationCache{
		mech:              mech,
		trustedIdentities: trustedIdentities,
	}, nil
}

func (pc *PolicyContext) initializeSignatureCache() {
	pc.verificationCacheByKeyData = map[string]verificationCache{}
	pc.verificationCacheByKeyPath = map[string]verificationCache{}
}

func (pc *PolicyContext) destroySignatureCache() {
	for _, c := range pc.verificationCacheByKeyData {
		_ = c.mech.Close()
	}
	for _, c := range pc.verificationCacheByKeyPath {
		_ = c.mech.Close()
	}
}

// verificationCache returns a verificationCache instance appopriate for pr, creating it if necessary.
func (pr *prSignedBy) verificationCache(pc *PolicyContext) (verificationCache, error) {
	switch {
	case pr.KeyPath != "" && pr.KeyData != nil:
		return verificationCache{}, errors.New(`Internal inconsistency: both "keyPath" and "keyData" specified`)

	case pr.KeyData != nil:
		if vc, ok := pc.verificationCacheByKeyData[string(pr.KeyData)]; ok {
			return vc, nil
		}
		vc, err := verificationCacheFromData(pr.KeyData)
		if err != nil {
			return verificationCache{}, err
		}
		pc.verificationCacheByKeyData[string(pr.KeyData)] = vc
		return vc, nil

	default: // Use pr.KeyPath
		if vc, ok := pc.verificationCacheByKeyPath[pr.KeyPath]; ok {
			return vc, nil
		}
		data, err := os.ReadFile(pr.KeyPath)
		if err != nil {
			return verificationCache{}, err
		}
		vc, err := verificationCacheFromData(data)
		if err != nil {
			return verificationCache{}, err
		}
		pc.verificationCacheByKeyPath[pr.KeyPath] = vc
		return vc, nil
	}
}

func (pr *prSignedBy) isSignatureAuthorAccepted(ctx context.Context, pc *PolicyContext, image types.UnparsedImage, sig []byte) (signatureAcceptanceResult, *Signature, error) {
	switch pr.KeyType {
	case SBKeyTypeGPGKeys:
	case SBKeyTypeSignedByGPGKeys, SBKeyTypeX509Certificates, SBKeyTypeSignedByX509CAs:
		// FIXME? Reject this at policy parsing time already?
		return sarRejected, nil, fmt.Errorf(`Unimplemented "keyType" value "%s"`, string(pr.KeyType))
	default:
		// This should never happen, newPRSignedBy ensures KeyType.IsValid()
		return sarRejected, nil, fmt.Errorf(`Unknown "keyType" value "%s"`, string(pr.KeyType))
	}

	vc, err := pr.verificationCache(pc)
	if err != nil {
		return sarRejected, nil, err
	}
	if len(vc.trustedIdentities) == 0 {
		return sarRejected, nil, PolicyRequirementError("No public keys imported")
	}

	signature, err := verifyAndExtractSignature(vc.mech, sig, signatureAcceptanceRules{
		validateKeyIdentity: func(keyIdentity string) error {
			for _, trustedIdentity := range vc.trustedIdentities {
				if keyIdentity == trustedIdentity {
					return nil
				}
			}
			// Coverage: We use a private GPG home directory and only import trusted keys, so this should
			// not be reachable.
			return PolicyRequirementError(fmt.Sprintf("Signature by key %s is not accepted", keyIdentity))
		},
		validateSignedDockerReference: func(ref string) error {
			if !pr.SignedIdentity.matchesDockerReference(image, ref) {
				return PolicyRequirementError(fmt.Sprintf("Signature for identity %s is not accepted", ref))
			}
			return nil
		},
		validateSignedDockerManifestDigest: func(digest digest.Digest) error {
			m, _, err := image.Manifest(ctx)
			if err != nil {
				return err
			}
			digestMatches, err := manifest.MatchesDigest(m, digest)
			if err != nil {
				return err
			}
			if !digestMatches {
				return PolicyRequirementError(fmt.Sprintf("Signature for digest %s does not match", digest))
			}
			return nil
		},
	})
	if err != nil {
		return sarRejected, nil, err
	}

	return sarAccepted, signature, nil
}

func (pr *prSignedBy) isRunningImageAllowed(ctx context.Context, pc *PolicyContext, image types.UnparsedImage) (bool, error) {
	// FIXME: pass context.Context
	sigs, err := image.Signatures(ctx)
	if err != nil {
		return false, err
	}
	var rejections []error
	for _, s := range sigs {
		var reason error
		switch res, _, err := pr.isSignatureAuthorAccepted(ctx, pc, image, s); res {
		case sarAccepted:
			// One accepted signature is enough.
			return true, nil
		case sarRejected:
			reason = err
		case sarUnknown:
			// Huh?! This should not happen at all; treat it as any other invalid value.
			fallthrough
		default:
			reason = fmt.Errorf(`Internal error: Unexpected signature verification result "%s"`, string(res))
		}
		rejections = append(rejections, reason)
	}
	var summary error
	switch len(rejections) {
	case 0:
		summary = PolicyRequirementError("A signature was required, but no signature exists")
	case 1:
		summary = rejections[0]
	default:
		var msgs []string
		for _, e := range rejections {
			msgs = append(msgs, e.Error())
		}
		summary = PolicyRequirementError(fmt.Sprintf("None of the signatures were accepted, reasons: %s",
			strings.Join(msgs, "; ")))
	}
	return false, summary
}
