package surface

import "github.com/solomonneas/agentpantry/internal/cookie"

// Surface is a sink-side destination for synced cookies.
type Surface interface {
	Apply(d cookie.Diff) error
}
