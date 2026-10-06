package normalize

import (
	"math"
	"sort"
	"strings"
	"time"

	"reconx/pkg/models"
)

// Options defines settings for asset normalization and deduplication.
type Options struct {
	TargetDomain string
	BaseConfidence float64
	SourceBonus    float64
	MaxConfidence  float64
}

// DefaultOptions provides standard scoring and filtering parameters.
func DefaultOptions(targetDomain string) Options {
	return Options{
		TargetDomain:   strings.ToLower(strings.TrimSpace(targetDomain)),
		BaseConfidence: 0.60,
		SourceBonus:    0.15,
		MaxConfidence:  0.98,
	}
}

// NormalizeAndDedup takes raw results from multiple providers, sanitizes them,
// merges duplicate findings across providers, and calculates a confidence score.
func NormalizeAndDedup(rawList []models.RawResult, opts Options) []models.Asset {
	now := time.Now().UTC()
	type intermediate struct {
		assetVal   string
		assetType  models.AssetType
		sources    map[string]bool
		firstSeen  time.Time
		lastSeen   time.Time
		maxConf    float64
		metadata   map[string]string
	}

	grouped := make(map[string]*intermediate)

	for _, raw := range rawList {
		val := strings.TrimSpace(strings.ToLower(raw.Value))
		// Strip wildcards
		val = strings.TrimPrefix(val, "*.")
		val = strings.TrimPrefix(val, ".")

		if val == "" {
			continue
		}

		// If a target domain is specified, enforce scope
		if opts.TargetDomain != "" {
			if val != opts.TargetDomain && !strings.HasSuffix(val, "."+opts.TargetDomain) {
				continue
			}
		}

		key := val + ":" + string(raw.Type)
		entry, exists := grouped[key]
		if !exists {
			entry = &intermediate{
				assetVal:  val,
				assetType: raw.Type,
				sources:   make(map[string]bool),
				// firstSeen/lastSeen left zero; populated from provider
				// metadata below, falling back to now at emit time.
				maxConf:  raw.Confidence,
				metadata: make(map[string]string),
			}
			grouped[key] = entry
		}

		// Derive real observation dates from provider metadata where available
		// (e.g. crt.sh certificate not_before / not_after, Wayback timestamps),
		// tracking the earliest first-seen and latest last-seen across sources.
		earliest, latest := extractObservationDates(raw.Metadata)
		if !earliest.IsZero() && (entry.firstSeen.IsZero() || earliest.Before(entry.firstSeen)) {
			entry.firstSeen = earliest
		}
		if !latest.IsZero() && latest.After(entry.lastSeen) {
			entry.lastSeen = latest
		}

		if raw.Source != "" {
			// Handle comma-separated source lists
			for _, s := range strings.Split(raw.Source, ",") {
				cleanSource := strings.TrimSpace(s)
				if cleanSource != "" {
					entry.sources[cleanSource] = true
				}
			}
		}

		if raw.Confidence > entry.maxConf {
			entry.maxConf = raw.Confidence
		}

		for k, v := range raw.Metadata {
			if _, has := entry.metadata[k]; !has && v != "" {
				entry.metadata[k] = v
			}
		}
	}

	assets := make([]models.Asset, 0, len(grouped))
	for _, item := range grouped {
		sourcesList := make([]string, 0, len(item.sources))
		for s := range item.sources {
			sourcesList = append(sourcesList, s)
		}
		sort.Strings(sourcesList)

		// Confidence formula: Base + 0.15 * (N - 1), capped at 0.98
		conf := opts.BaseConfidence
		if item.maxConf > conf {
			conf = item.maxConf
		}
		if len(sourcesList) > 1 {
			conf += opts.SourceBonus * float64(len(sourcesList)-1)
		}
		conf = math.Min(opts.MaxConfidence, conf)

		firstSeen := item.firstSeen
		if firstSeen.IsZero() {
			firstSeen = now
		}
		lastSeen := item.lastSeen
		if lastSeen.IsZero() {
			lastSeen = now
		}

		assets = append(assets, models.Asset{
			Asset:      item.assetVal,
			Type:       item.assetType,
			Sources:    sourcesList,
			FirstSeen:  firstSeen,
			LastSeen:   lastSeen,
			Confidence: math.Round(conf*100) / 100,
		})
	}

	// Sort alphabetically by asset name
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].Asset < assets[j].Asset
	})

	return assets
}

// dateLayouts lists the timestamp formats emitted by the passive providers
// (crt.sh uses an RFC3339-like form without a zone; Wayback uses a 14-digit
// compact stamp).
var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"20060102150405", // Wayback CDX timestamp
}

// parseFlexibleTime attempts each known layout and returns the first match.
func parseFlexibleTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// extractObservationDates pulls first-seen / last-seen hints out of a provider's
// metadata. It understands certificate validity (not_before / not_after),
// CT-log entry timestamps, and Wayback snapshot stamps. Zero times are returned
// when nothing parseable is present.
func extractObservationDates(meta map[string]string) (earliest, latest time.Time) {
	if meta == nil {
		return time.Time{}, time.Time{}
	}

	consider := func(key string, asEarliest, asLatest bool) {
		t := parseFlexibleTime(meta[key])
		if t.IsZero() {
			return
		}
		if asEarliest && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
		if asLatest && t.After(latest) {
			latest = t
		}
	}

	// Certificate issuance marks when the host first became observable; its
	// expiry and the CT entry time bound the most recent observation.
	consider("not_before", true, false)
	consider("not_after", false, true)
	consider("entry_timestamp", true, true)
	consider("timestamp", true, true)
	consider("first_seen", true, false)
	consider("last_seen", false, true)

	return earliest, latest
}
