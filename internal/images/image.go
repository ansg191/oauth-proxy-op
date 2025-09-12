package images

import (
	"context"

	"github.com/blang/semver/v4"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	defaultRepo = "quay.io/oauth2-proxy/oauth2-proxy"
)

var DefaultRepo = func() name.Repository {
	repo, err := name.NewRepository(defaultRepo)
	if err != nil {
		panic(err)
	}
	return repo
}()

type Registry interface {
	LatestImage(ctx context.Context, repo name.Repository) (name.Reference, error)
}

type ociRegistry struct{}

func NewOCIRegistry() Registry {
	return ociRegistry{}
}

func (ociRegistry) LatestImage(ctx context.Context, repo name.Repository) (name.Reference, error) {
	tags, err := remote.List(repo, remote.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	var latest semver.Version
	var latestStr string
	for _, tag := range tags {
		v, err := semver.ParseTolerant(tag)
		if err != nil {
			continue
		}
		if latest.LT(v) {
			latest = v
			latestStr = tag
		}
	}

	return repo.Tag(latestStr), nil
}
