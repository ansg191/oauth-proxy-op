package images

import (
	"context"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"k8s.io/utils/clock"
)

const refreshInterval = 1 * time.Hour

type imageCache struct {
	inner       Registry
	clock       clock.PassiveClock
	mtx         sync.Mutex
	latest      name.Reference
	lastUpdated time.Time
}

func NewRegistryCache(registry Registry) Registry {
	return NewRegistryCacheWithClock(registry, clock.RealClock{})
}

func NewRegistryCacheWithClock(registry Registry, cl clock.PassiveClock) Registry {
	return &imageCache{
		inner: registry,
		clock: cl,
	}
}

func (c *imageCache) LatestImage(ctx context.Context, repo name.Repository) (name.Reference, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.latest == nil || c.clock.Since(c.lastUpdated) > refreshInterval {
		var err error
		c.latest, err = c.inner.LatestImage(ctx, repo)
		if err != nil {
			return nil, err
		}
		c.lastUpdated = c.clock.Now()
	}
	return c.latest, nil
}
