// Policy evaluation for prSignedBaseLayer.

package signature

import (
	"context"

	"github.com/containers/image/v5/types"
	"github.com/sirupsen/logrus"
)

func (pr *prSignedBaseLayer) isSignatureAuthorAccepted(ctx context.Context, pc *PolicyContext, image types.UnparsedImage, sig []byte) (signatureAcceptanceResult, *Signature, error) {
	return sarUnknown, nil, nil
}

func (pr *prSignedBaseLayer) isRunningImageAllowed(ctx context.Context, pc *PolicyContext, image types.UnparsedImage) (bool, error) {
	// FIXME? Reject this at policy parsing time already?
	logrus.Errorf("signedBaseLayer not implemented yet!")
	return false, PolicyRequirementError("signedBaseLayer not implemented yet!")
}
