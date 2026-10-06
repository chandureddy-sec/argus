package providers

import (
	"context"
	"time"

	"reconx/pkg/models"
)

// Provider defines the standard contract that every passive OSINT source must implement.
type Provider interface {
	// Name returns the unique identifier of the provider (e.g. "crtsh", "virustotal").
	Name() string

	// Supports returns true if this provider can gather intelligence on the given target type.
	Supports(t models.Target) bool

	// Collect performs the passive information gathering query against the provider.
	Collect(ctx context.Context, t models.Target) ([]models.RawResult, error)

	// RateLimit specifies the minimum delay between consecutive calls to this provider.
	RateLimit() time.Duration
}

// Registry maintains the collection of all available providers.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry initializes an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(p Provider) {
	r.providers[p.Name()] = p
}

// GetAll returns all registered providers.
func (r *Registry) GetAll() []Provider {
	list := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		list = append(list, p)
	}
	return list
}

// GetSupported returns providers that support the given target.
func (r *Registry) GetSupported(t models.Target) []Provider {
	var supported []Provider
	for _, p := range r.providers {
		if p.Supports(t) {
			supported = append(supported, p)
		}
	}
	return supported
}
