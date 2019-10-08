/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/linki/instrumented_http"
	log "github.com/sirupsen/logrus"
)

const (
	recordTTL = 300
	// provider specific key that designates whether an AWS ALIAS record has the EvaluateTargetHealth
	// field set to true.
	providerSpecificEvaluateTargetHealth       = "aws/evaluate-target-health"
	providerSpecificWeight                     = "aws/weight"
	providerSpecificRegion                     = "aws/region"
	providerSpecificFailover                   = "aws/failover"
	providerSpecificGeolocationContinentCode   = "aws/geolocation-continent-code"
	providerSpecificGeolocationCountryCode     = "aws/geolocation-country-code"
	providerSpecificGeolocationSubdivisionCode = "aws/geolocation-subdivision-code"
	providerSpecificMultiValueAnswer           = "aws/multi-value-answer"
	providerSpecificHealthCheckID              = "aws/health-check-id"

	providerSpecificHealthCheckDisabled         = "aws/health-check-disabled"
	providerSpecificHealthCheckEnableSNI        = "aws/health-check-enable-sni"
	providerSpecificHealthCheckFailureThreshold = "aws/health-check-failure-threshold"
	providerSpecificHealthCheckFQDN             = "aws/health-check-fqdn"
	providerSpecificHealthCheckInverted         = "aws/health-check-inverted"
	providerSpecificHealthCheckPort             = "aws/health-check-port"
	providerSpecificHealthCheckRequestInterval  = "aws/health-check-interval"
	providerSpecificHealthCheckResourcePath     = "aws/health-check-resource-path"
	providerSpecificHealthCheckType             = "aws/health-check-type"
)

var (
	// see: https://docs.aws.amazon.com/general/latest/gr/rande.html#elb_region
	canonicalHostedZones = map[string]string{
		// Application Load Balancers and Classic Load Balancers
		"us-east-2.elb.amazonaws.com":         "Z3AADJGX6KTTL2",
		"us-east-1.elb.amazonaws.com":         "Z35SXDOTRQ7X7K",
		"us-west-1.elb.amazonaws.com":         "Z368ELLRRE2KJ0",
		"us-west-2.elb.amazonaws.com":         "Z1H1FL5HABSF5",
		"ca-central-1.elb.amazonaws.com":      "ZQSVJUPU6J1EY",
		"ap-south-1.elb.amazonaws.com":        "ZP97RAFLXTNZK",
		"ap-northeast-2.elb.amazonaws.com":    "ZWKZPGTI48KDX",
		"ap-northeast-3.elb.amazonaws.com":    "Z5LXEXXYW11ES",
		"ap-southeast-1.elb.amazonaws.com":    "Z1LMS91P8CMLE5",
		"ap-southeast-2.elb.amazonaws.com":    "Z1GM3OXH4ZPM65",
		"ap-northeast-1.elb.amazonaws.com":    "Z14GRHDCWA56QT",
		"eu-central-1.elb.amazonaws.com":      "Z215JYRZR1TBD5",
		"eu-west-1.elb.amazonaws.com":         "Z32O12XQLNTSW2",
		"eu-west-2.elb.amazonaws.com":         "ZHURV8PSTC4K8",
		"eu-west-3.elb.amazonaws.com":         "Z3Q77PNBQS71R4",
		"eu-north-1.elb.amazonaws.com":        "Z23TAZ6LKFMNIO",
		"sa-east-1.elb.amazonaws.com":         "Z2P70J7HTTTPLU",
		"cn-north-1.elb.amazonaws.com.cn":     "Z3BX2TMKNYI13Y",
		"cn-northwest-1.elb.amazonaws.com.cn": "Z3BX2TMKNYI13Y",
		// Network Load Balancers
		"elb.us-east-2.amazonaws.com":         "ZLMOA37VPKANP",
		"elb.us-east-1.amazonaws.com":         "Z26RNL4JYFTOTI",
		"elb.us-west-1.amazonaws.com":         "Z24FKFUX50B4VW",
		"elb.us-west-2.amazonaws.com":         "Z18D5FSROUN65G",
		"elb.ca-central-1.amazonaws.com":      "Z2EPGBW3API2WT",
		"elb.ap-south-1.amazonaws.com":        "ZVDDRBQ08TROA",
		"elb.ap-northeast-2.amazonaws.com":    "ZIBE1TIR4HY56",
		"elb.ap-southeast-1.amazonaws.com":    "ZKVM4W9LS7TM",
		"elb.ap-southeast-2.amazonaws.com":    "ZCT6FZBF4DROD",
		"elb.ap-northeast-1.amazonaws.com":    "Z31USIVHYNEOWT",
		"elb.eu-central-1.amazonaws.com":      "Z3F0SRJ5LGBH90",
		"elb.eu-west-1.amazonaws.com":         "Z2IFOLAFXWLO4F",
		"elb.eu-west-2.amazonaws.com":         "ZD4D7Y8KGAS4G",
		"elb.eu-west-3.amazonaws.com":         "Z1CMS0P5QUZ6D5",
		"elb.eu-north-1.amazonaws.com":        "Z1UDT6IFJ4EJM",
		"elb.sa-east-1.amazonaws.com":         "ZTK26PT1VY4CU",
		"elb.cn-north-1.amazonaws.com.cn":     "Z3QFB96KMJ7ED6",
		"elb.cn-northwest-1.amazonaws.com.cn": "ZQEIKTCZ8352D",
	}
)

// Route53API is the subset of the AWS Route53 API that we actually use.  Add methods as required. Signatures must match exactly.
// mostly taken from: https://github.com/kubernetes/kubernetes/blob/853167624edb6bc0cfdcdfb88e746e178f5db36c/federation/pkg/dnsprovider/providers/aws/route53/stubs/route53api.go
type Route53API interface {
	ListResourceRecordSetsPages(input *route53.ListResourceRecordSetsInput, fn func(resp *route53.ListResourceRecordSetsOutput, lastPage bool) (shouldContinue bool)) error
	ChangeResourceRecordSets(*route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error)
	CreateHostedZone(*route53.CreateHostedZoneInput) (*route53.CreateHostedZoneOutput, error)
	ListHostedZonesPages(input *route53.ListHostedZonesInput, fn func(resp *route53.ListHostedZonesOutput, lastPage bool) (shouldContinue bool)) error
	ListTagsForResource(input *route53.ListTagsForResourceInput) (*route53.ListTagsForResourceOutput, error)
	GetHealthCheck(input *route53.GetHealthCheckInput) (*route53.GetHealthCheckOutput, error)
	CreateHealthCheck(input *route53.CreateHealthCheckInput) (*route53.CreateHealthCheckOutput, error)
	ChangeTagsForResource(input *route53.ChangeTagsForResourceInput) (*route53.ChangeTagsForResourceOutput, error)
	ListHealthChecks(input *route53.ListHealthChecksInput) (*route53.ListHealthChecksOutput, error)
}

// AWSProvider is an implementation of Provider for AWS Route53.
type AWSProvider struct {
	client               Route53API
	dryRun               bool
	batchChangeSize      int
	batchChangeInterval  time.Duration
	evaluateTargetHealth bool
	// only consider hosted zones managing domains ending in this suffix
	domainFilter DomainFilter
	// filter hosted zones by id
	zoneIDFilter ZoneIDFilter
	// filter hosted zones by type (e.g. private or public)
	zoneTypeFilter ZoneTypeFilter
	// filter hosted zones by tags
	zoneTagFilter ZoneTagFilter
	preferCNAME   bool
	healthChecks  []healthCheck
}

// AWSConfig contains configuration to create a new AWS provider.
type AWSConfig struct {
	DomainFilter         DomainFilter
	ZoneIDFilter         ZoneIDFilter
	ZoneTypeFilter       ZoneTypeFilter
	ZoneTagFilter        ZoneTagFilter
	BatchChangeSize      int
	BatchChangeInterval  time.Duration
	EvaluateTargetHealth bool
	AssumeRole           string
	APIRetries           int
	PreferCNAME          bool
	DryRun               bool
}

// NewAWSProvider initializes a new AWS Route53 based Provider.
func NewAWSProvider(awsConfig AWSConfig) (*AWSProvider, error) {
	config := aws.NewConfig().WithMaxRetries(awsConfig.APIRetries)

	config.WithHTTPClient(
		instrumented_http.NewClient(config.HTTPClient, &instrumented_http.Callbacks{
			PathProcessor: func(path string) string {
				parts := strings.Split(path, "/")
				return parts[len(parts)-1]
			},
		}),
	)

	session, err := session.NewSessionWithOptions(session.Options{
		Config:            *config,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	if awsConfig.AssumeRole != "" {
		log.Infof("Assuming role: %s", awsConfig.AssumeRole)
		session.Config.WithCredentials(stscreds.NewCredentials(session, awsConfig.AssumeRole))
	}

	provider := &AWSProvider{
		client:               route53.New(session),
		domainFilter:         awsConfig.DomainFilter,
		zoneIDFilter:         awsConfig.ZoneIDFilter,
		zoneTypeFilter:       awsConfig.ZoneTypeFilter,
		zoneTagFilter:        awsConfig.ZoneTagFilter,
		batchChangeSize:      awsConfig.BatchChangeSize,
		batchChangeInterval:  awsConfig.BatchChangeInterval,
		evaluateTargetHealth: awsConfig.EvaluateTargetHealth,
		preferCNAME:          awsConfig.PreferCNAME,
		dryRun:               awsConfig.DryRun,
	}

	return provider, nil
}

// Zones returns the list of hosted zones.
func (p *AWSProvider) Zones() (map[string]*route53.HostedZone, error) {
	zones := make(map[string]*route53.HostedZone)

	var tagErr error
	f := func(resp *route53.ListHostedZonesOutput, lastPage bool) (shouldContinue bool) {
		for _, zone := range resp.HostedZones {
			if !p.zoneIDFilter.Match(aws.StringValue(zone.Id)) {
				continue
			}

			if !p.zoneTypeFilter.Match(zone) {
				continue
			}

			if !p.domainFilter.Match(aws.StringValue(zone.Name)) {
				continue
			}

			// Only fetch tags if a tag filter was specified
			if !p.zoneTagFilter.IsEmpty() {
				tags, err := p.tagsForZone(*zone.Id)
				if err != nil {
					tagErr = err
					return false
				}
				if !p.zoneTagFilter.Match(tags) {
					continue
				}
			}

			zones[aws.StringValue(zone.Id)] = zone
		}

		return true
	}

	err := p.client.ListHostedZonesPages(&route53.ListHostedZonesInput{}, f)
	if err != nil {
		return nil, err
	}
	if tagErr != nil {
		return nil, tagErr
	}

	for _, zone := range zones {
		log.Debugf("Considering zone: %s (domain: %s)", aws.StringValue(zone.Id), aws.StringValue(zone.Name))
	}

	return zones, nil
}

// wildcardUnescape converts \\052.abc back to *.abc
// Route53 stores wildcards escaped: http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html?shortFooter=true#domain-name-format-asterisk
func wildcardUnescape(s string) string {
	if strings.Contains(s, "\\052") {
		s = strings.Replace(s, "\\052", "*", 1)
	}
	return s
}

// Records returns the list of records in a given hosted zone.
func (p *AWSProvider) Records() (endpoints []*endpoint.Endpoint, _ error) {
	zones, err := p.Zones()
	if err != nil {
		return nil, err
	}

	return p.records(zones)
}

func (p *AWSProvider) records(zones map[string]*route53.HostedZone) ([]*endpoint.Endpoint, error) {
	endpoints := make([]*endpoint.Endpoint, 0)
	f := func(resp *route53.ListResourceRecordSetsOutput, lastPage bool) (shouldContinue bool) {
		for _, r := range resp.ResourceRecordSets {
			newEndpoints := make([]*endpoint.Endpoint, 0)

			// TODO(linki, ownership): Remove once ownership system is in place.
			// See: https://github.com/kubernetes-incubator/external-dns/pull/122/files/74e2c3d3e237411e619aefc5aab694742001cdec#r109863370

			if !supportedRecordType(aws.StringValue(r.Type)) {
				continue
			}

			var ttl endpoint.TTL
			if r.TTL != nil {
				ttl = endpoint.TTL(*r.TTL)
			}

			if len(r.ResourceRecords) > 0 {
				targets := make([]string, len(r.ResourceRecords))
				for idx, rr := range r.ResourceRecords {
					targets[idx] = aws.StringValue(rr.Value)
				}

				newEndpoints = append(newEndpoints, endpoint.NewEndpointWithTTL(wildcardUnescape(aws.StringValue(r.Name)), aws.StringValue(r.Type), ttl, targets...))
			}

			if r.AliasTarget != nil {
				// Alias records don't have TTLs so provide the default to match the TXT generation
				if ttl == 0 {
					ttl = recordTTL
				}
				ep := endpoint.
					NewEndpointWithTTL(wildcardUnescape(aws.StringValue(r.Name)), endpoint.RecordTypeCNAME, ttl, aws.StringValue(r.AliasTarget.DNSName)).
					WithProviderSpecific(providerSpecificEvaluateTargetHealth, fmt.Sprintf("%t", aws.BoolValue(r.AliasTarget.EvaluateTargetHealth)))
				newEndpoints = append(newEndpoints, ep)
			}

			for _, ep := range newEndpoints {
				if r.SetIdentifier != nil {
					ep.SetIdentifier = aws.StringValue(r.SetIdentifier)

					if r.HealthCheckId != nil {
						tags, err := p.tagsForHealthCheck(aws.StringValue(r.HealthCheckId))
						if err != nil {
							log.Errorf("failed to get health check tags for health check id %s. error: %v", aws.StringValue(r.HealthCheckId), err)
							return false
						}

						if isExternalDNSOwner(tags) == false {
							// this check was not created by external-dns
							ep.WithProviderSpecific(providerSpecificHealthCheckID, aws.StringValue(r.HealthCheckId))
						} else {
							// this health id was created by external-dns, so dont add healthCheckId it to providerSpecific
							// instead get the health check config and convert them to providerspecific
							// because those annotations were most likely used to create the health check
							// so we will need these to compare them with what is in the source annotations
							// and make changes accordingly.
							healthCheck, err := p.getHealthCheck(aws.StringValue(r.HealthCheckId))
							if err != nil {
								log.Errorf("failed to get health check with id %q. error: %v", aws.StringValue(r.HealthCheckId), err)
								return false
							}
							healthCheckConfigToProviderSpecific(healthCheck.HealthCheckConfig, ep)
						}
					}

					switch {
					case r.Weight != nil:
						ep.WithProviderSpecific(providerSpecificWeight, fmt.Sprintf("%d", aws.Int64Value(r.Weight)))
					case r.Region != nil:
						ep.WithProviderSpecific(providerSpecificRegion, aws.StringValue(r.Region))
					case r.Failover != nil:
						ep.WithProviderSpecific(providerSpecificFailover, aws.StringValue(r.Failover))
					case r.MultiValueAnswer != nil && aws.BoolValue(r.MultiValueAnswer):
						ep.WithProviderSpecific(providerSpecificMultiValueAnswer, "")
					case r.GeoLocation != nil:
						if r.GeoLocation.ContinentCode != nil {
							ep.WithProviderSpecific(providerSpecificGeolocationContinentCode, aws.StringValue(r.GeoLocation.ContinentCode))
						} else {
							if r.GeoLocation.CountryCode != nil {
								ep.WithProviderSpecific(providerSpecificGeolocationCountryCode, aws.StringValue(r.GeoLocation.CountryCode))
							}
							if r.GeoLocation.SubdivisionCode != nil {
								ep.WithProviderSpecific(providerSpecificGeolocationSubdivisionCode, aws.StringValue(r.GeoLocation.SubdivisionCode))
							}
						}
					default:
						// one of the above needs to be set, otherwise SetIdentifier doesn't make sense
					}
				}
				endpoints = append(endpoints, ep)
			}
		}

		return true
	}

	for _, z := range zones {
		params := &route53.ListResourceRecordSetsInput{
			HostedZoneId: z.Id,
		}

		if err := p.client.ListResourceRecordSetsPages(params, f); err != nil {
			return nil, err
		}
	}

	return endpoints, nil
}

// CreateRecords creates a given set of DNS records in the given hosted zone.
func (p *AWSProvider) CreateRecords(endpoints []*endpoint.Endpoint) error {
	return p.doRecords(route53.ChangeActionCreate, endpoints)
}

// UpdateRecords updates a given set of old records to a new set of records in a given hosted zone.
func (p *AWSProvider) UpdateRecords(endpoints, _ []*endpoint.Endpoint) error {
	return p.doRecords(route53.ChangeActionUpsert, endpoints)
}

// DeleteRecords deletes a given set of DNS records in a given zone.
func (p *AWSProvider) DeleteRecords(endpoints []*endpoint.Endpoint) error {
	return p.doRecords(route53.ChangeActionDelete, endpoints)
}

func (p *AWSProvider) doRecords(action string, endpoints []*endpoint.Endpoint) error {
	zones, err := p.Zones()
	if err != nil {
		return err
	}

	records, err := p.records(zones)
	if err != nil {
		log.Errorf("getting records failed: %v", err)
	}
	return p.submitChanges(p.newChanges(action, endpoints, records, zones), zones)
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *AWSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	zones, err := p.Zones()
	if err != nil {
		return err
	}

	p.updateHealthChecksCache()

	records, ok := ctx.Value(RecordsContextKey).([]*endpoint.Endpoint)
	if !ok {
		var err error
		records, err = p.records(zones)
		if err != nil {
			log.Errorf("getting records failed: %v", err)
		}
	}

	combinedChanges := make([]*route53.Change, 0, len(changes.Create)+len(changes.UpdateNew)+len(changes.Delete))

	combinedChanges = append(combinedChanges, p.newChanges(route53.ChangeActionCreate, changes.Create, records, zones)...)
	combinedChanges = append(combinedChanges, p.newChanges(route53.ChangeActionUpsert, changes.UpdateNew, records, zones)...)
	combinedChanges = append(combinedChanges, p.newChanges(route53.ChangeActionDelete, changes.Delete, records, zones)...)

	return p.submitChanges(combinedChanges, zones)
}

// submitChanges takes a zone and a collection of Changes and sends them as a single transaction.
func (p *AWSProvider) submitChanges(changes []*route53.Change, zones map[string]*route53.HostedZone) error {
	// return early if there is nothing to change
	if len(changes) == 0 {
		log.Info("All records are already up to date")
		return nil
	}

	// separate into per-zone change sets to be passed to the API.
	changesByZone := changesByZone(zones, changes)
	if len(changesByZone) == 0 {
		log.Info("All records are already up to date, there are no changes for the matching hosted zones")
	}

	var failedZones []string
	for z, cs := range changesByZone {
		var failedUpdate bool

		batchCs := batchChangeSet(cs, p.batchChangeSize)

		for i, b := range batchCs {
			for _, c := range b {
				log.Infof("Desired change: %s %s %s [Id: %s]", *c.Action, *c.ResourceRecordSet.Name, *c.ResourceRecordSet.Type, z)
			}

			if !p.dryRun {
				params := &route53.ChangeResourceRecordSetsInput{
					HostedZoneId: aws.String(z),
					ChangeBatch: &route53.ChangeBatch{
						Changes: b,
					},
				}

				if _, err := p.client.ChangeResourceRecordSets(params); err != nil {
					log.Errorf("Failure in zone %s [Id: %s]", aws.StringValue(zones[z].Name), z)
					log.Error(err) //TODO(ideahitme): consider changing the interface in cases when this error might be a concern for other components
					failedUpdate = true
				} else {
					// z is the R53 Hosted Zone ID already as aws.StringValue
					log.Infof("%d record(s) in zone %s [Id: %s] were successfully updated", len(b), aws.StringValue(zones[z].Name), z)
				}

				if i != len(batchCs)-1 {
					time.Sleep(p.batchChangeInterval)
				}
			}
		}

		if failedUpdate {
			failedZones = append(failedZones, z)
		}
	}

	if len(failedZones) > 0 {
		return fmt.Errorf("Failed to submit all changes for the following zones: %v", failedZones)
	}

	return nil
}

// newChanges returns a collection of Changes based on the given records and action.
func (p *AWSProvider) newChanges(action string, endpoints []*endpoint.Endpoint, recordsCache []*endpoint.Endpoint, zones map[string]*route53.HostedZone) []*route53.Change {
	changes := make([]*route53.Change, 0, len(endpoints))

	for _, endpoint := range endpoints {
		change, dualstack := p.newChange(action, endpoint, recordsCache, zones)
		changes = append(changes, change)
		if dualstack {
			// make a copy of change, modify RRS type to AAAA, then add new change
			rrs := *change.ResourceRecordSet
			change2 := &route53.Change{Action: change.Action, ResourceRecordSet: &rrs}
			change2.ResourceRecordSet.Type = aws.String(route53.RRTypeAaaa)
			changes = append(changes, change2)
		}
	}

	return changes
}

// newChange returns a route53 Change and a boolean indicating if there should also be a change to a AAAA record
// returned Change is based on the given record by the given action, e.g.
// action=ChangeActionCreate returns a change for creation of the record and
// action=ChangeActionDelete returns a change for deletion of the record.
func (p *AWSProvider) newChange(action string, ep *endpoint.Endpoint, recordsCache []*endpoint.Endpoint, zones map[string]*route53.HostedZone) (*route53.Change, bool) {
	change := &route53.Change{
		Action: aws.String(action),
		ResourceRecordSet: &route53.ResourceRecordSet{
			Name: aws.String(ep.DNSName),
		},
	}
	dualstack := false

	if useAlias(ep, p.preferCNAME) {
		evalTargetHealth := p.evaluateTargetHealth
		if prop, ok := ep.GetProviderSpecificProperty(providerSpecificEvaluateTargetHealth); ok {
			evalTargetHealth = prop.Value == "true"
		}
		// If the endpoint has a Dualstack label, append a change for AAAA record as well.
		if val, ok := ep.Labels[endpoint.DualstackLabelKey]; ok {
			dualstack = val == "true"
		}

		change.ResourceRecordSet.Type = aws.String(route53.RRTypeA)
		change.ResourceRecordSet.AliasTarget = &route53.AliasTarget{
			DNSName:              aws.String(ep.Targets[0]),
			HostedZoneId:         aws.String(canonicalHostedZone(ep.Targets[0])),
			EvaluateTargetHealth: aws.Bool(evalTargetHealth),
		}
	} else if hostedZone := isAWSAlias(ep, recordsCache); hostedZone != "" {
		for _, zone := range zones {
			change.ResourceRecordSet.Type = aws.String(route53.RRTypeA)
			change.ResourceRecordSet.AliasTarget = &route53.AliasTarget{
				DNSName:              aws.String(ep.Targets[0]),
				HostedZoneId:         aws.String(cleanZoneID(*zone.Id)),
				EvaluateTargetHealth: aws.Bool(p.evaluateTargetHealth),
			}
		}
	} else {
		change.ResourceRecordSet.Type = aws.String(ep.RecordType)
		if !ep.RecordTTL.IsConfigured() {
			change.ResourceRecordSet.TTL = aws.Int64(recordTTL)
		} else {
			change.ResourceRecordSet.TTL = aws.Int64(int64(ep.RecordTTL))
		}
		change.ResourceRecordSet.ResourceRecords = make([]*route53.ResourceRecord, len(ep.Targets))
		for idx, val := range ep.Targets {
			change.ResourceRecordSet.ResourceRecords[idx] = &route53.ResourceRecord{
				Value: aws.String(val),
			}
		}
	}

	setIdentifier := ep.SetIdentifier
	if setIdentifier != "" {
		change.ResourceRecordSet.SetIdentifier = aws.String(setIdentifier)
		if prop, ok := ep.GetProviderSpecificProperty(providerSpecificWeight); ok {
			weight, err := strconv.ParseInt(prop.Value, 10, 64)
			if err != nil {
				log.Errorf("Failed parsing value of %s: %s: %v; using weight of 0", providerSpecificWeight, prop.Value, err)
				weight = 0
			}
			change.ResourceRecordSet.Weight = aws.Int64(weight)
		}
		if prop, ok := ep.GetProviderSpecificProperty(providerSpecificRegion); ok {
			change.ResourceRecordSet.Region = aws.String(prop.Value)
		}
		if prop, ok := ep.GetProviderSpecificProperty(providerSpecificFailover); ok {
			change.ResourceRecordSet.Failover = aws.String(prop.Value)
		}
		if _, ok := ep.GetProviderSpecificProperty(providerSpecificMultiValueAnswer); ok {
			change.ResourceRecordSet.MultiValueAnswer = aws.Bool(true)
		}

		var geolocation = &route53.GeoLocation{}
		useGeolocation := false
		if prop, ok := ep.GetProviderSpecificProperty(providerSpecificGeolocationContinentCode); ok {
			geolocation.ContinentCode = aws.String(prop.Value)
			useGeolocation = true
		} else {
			if prop, ok := ep.GetProviderSpecificProperty(providerSpecificGeolocationCountryCode); ok {
				geolocation.CountryCode = aws.String(prop.Value)
				useGeolocation = true
			}
			if prop, ok := ep.GetProviderSpecificProperty(providerSpecificGeolocationSubdivisionCode); ok {
				geolocation.SubdivisionCode = aws.String(prop.Value)
				useGeolocation = true
			}
		}
		if useGeolocation {
			change.ResourceRecordSet.GeoLocation = geolocation
		}

		if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckID); ok {
			change.ResourceRecordSet.HealthCheckId = aws.String(prop.Value)
		} else {
			healthCheckID, err := p.createHealthCheckIfNeeded(ep)
			if err != nil {
				log.Error(err.Error())
			}

			if healthCheckID != "" {
				change.ResourceRecordSet.HealthCheckId = aws.String(healthCheckID)
			}
		}
	}

	return change, dualstack
}

func (p *AWSProvider) tagsForZone(zoneID string) (map[string]string, error) {
	return p.tagsForResource(zoneID, route53.TagResourceTypeHostedzone)
}

func (p *AWSProvider) tagsForHealthCheck(zoneID string) (map[string]string, error) {
	return p.tagsForResource(zoneID, route53.TagResourceTypeHealthcheck)
}

func (p *AWSProvider) tagsForResource(resourceID, resourceType string) (map[string]string, error) {
	response, err := p.client.ListTagsForResource(&route53.ListTagsForResourceInput{
		ResourceType: aws.String(resourceType),
		ResourceId:   aws.String(resourceID),
	})
	if err != nil {
		return nil, err
	}
	tagMap := map[string]string{}
	for _, tag := range response.ResourceTagSet.Tags {
		tagMap[*tag.Key] = *tag.Value
	}
	return tagMap, nil
}

func batchChangeSet(cs []*route53.Change, batchSize int) [][]*route53.Change {
	if len(cs) <= batchSize {
		return [][]*route53.Change{cs}
	}

	batchChanges := make([][]*route53.Change, 0)

	changesByName := make(map[string][]*route53.Change, 0)
	for _, v := range cs {
		changesByName[*v.ResourceRecordSet.Name] = append(changesByName[*v.ResourceRecordSet.Name], v)
	}

	names := make([]string, 0)
	for v := range changesByName {
		names = append(names, v)
	}
	sort.Strings(names)

	for _, name := range names {
		totalChangesByName := len(changesByName[name])

		if totalChangesByName > batchSize {
			log.Warnf("Total changes for %s exceeds max batch size of %d, total changes: %d", name,
				batchSize, totalChangesByName)
			continue
		}

		var existingBatch bool
		for i, b := range batchChanges {
			if len(b)+totalChangesByName <= batchSize {
				batchChanges[i] = append(batchChanges[i], changesByName[name]...)
				existingBatch = true
				break
			}
		}
		if !existingBatch {
			batchChanges = append(batchChanges, changesByName[name])
		}
	}

	for i, batch := range batchChanges {
		batchChanges[i] = sortChangesByActionNameType(batch)
	}

	return batchChanges
}

func sortChangesByActionNameType(cs []*route53.Change) []*route53.Change {
	sort.SliceStable(cs, func(i, j int) bool {
		if *cs[i].Action < *cs[j].Action {
			return true
		}
		if *cs[i].Action > *cs[j].Action {
			return false
		}
		if *cs[i].ResourceRecordSet.Name < *cs[j].ResourceRecordSet.Name {
			return true
		}
		if *cs[i].ResourceRecordSet.Name > *cs[j].ResourceRecordSet.Name {
			return false
		}
		return *cs[i].ResourceRecordSet.Type < *cs[j].ResourceRecordSet.Type
	})

	return cs
}

// changesByZone separates a multi-zone change into a single change per zone.
func changesByZone(zones map[string]*route53.HostedZone, changeSet []*route53.Change) map[string][]*route53.Change {
	changes := make(map[string][]*route53.Change)

	for _, z := range zones {
		changes[aws.StringValue(z.Id)] = []*route53.Change{}
	}

	for _, c := range changeSet {
		hostname := ensureTrailingDot(aws.StringValue(c.ResourceRecordSet.Name))

		zones := suitableZones(hostname, zones)
		if len(zones) == 0 {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected ", c.String())
			continue
		}
		for _, z := range zones {
			changes[aws.StringValue(z.Id)] = append(changes[aws.StringValue(z.Id)], c)
			log.Debugf("Adding %s to zone %s [Id: %s]", hostname, aws.StringValue(z.Name), aws.StringValue(z.Id))
		}
	}

	// separating a change could lead to empty sub changes, remove them here.
	for zone, change := range changes {
		if len(change) == 0 {
			delete(changes, zone)
		}
	}

	return changes
}

// suitableZones returns all suitable private zones and the most suitable public zone
//   for a given hostname and a set of zones.
func suitableZones(hostname string, zones map[string]*route53.HostedZone) []*route53.HostedZone {
	var matchingZones []*route53.HostedZone
	var publicZone *route53.HostedZone

	for _, z := range zones {
		if aws.StringValue(z.Name) == hostname || strings.HasSuffix(hostname, "."+aws.StringValue(z.Name)) {
			if z.Config == nil || !aws.BoolValue(z.Config.PrivateZone) {
				// Only select the best matching public zone
				if publicZone == nil || len(aws.StringValue(z.Name)) > len(aws.StringValue(publicZone.Name)) {
					publicZone = z
				}
			} else {
				// Include all private zones
				matchingZones = append(matchingZones, z)
			}
		}
	}

	if publicZone != nil {
		matchingZones = append(matchingZones, publicZone)
	}

	return matchingZones
}

// useAlias determines if AWS ALIAS should be used.
func useAlias(ep *endpoint.Endpoint, preferCNAME bool) bool {
	if preferCNAME {
		return false
	}

	if ep.RecordType == endpoint.RecordTypeCNAME && len(ep.Targets) > 0 {
		return canonicalHostedZone(ep.Targets[0]) != ""
	}

	return false
}

// isAWSAlias determines if a given hostname belongs to an AWS Alias record by doing an reverse lookup.
func isAWSAlias(ep *endpoint.Endpoint, addrs []*endpoint.Endpoint) string {
	if prop, exists := ep.GetProviderSpecificProperty("alias"); ep.RecordType == endpoint.RecordTypeCNAME && exists && prop.Value == "true" {
		for _, addr := range addrs {
			if len(ep.Targets) > 0 && addr.DNSName == ep.Targets[0] {
				if hostedZone := canonicalHostedZone(addr.Targets[0]); hostedZone != "" {
					return hostedZone
				}

			}
		}
	}
	return ""
}

// canonicalHostedZone returns the matching canonical zone for a given hostname.
func canonicalHostedZone(hostname string) string {
	for suffix, zone := range canonicalHostedZones {
		if strings.HasSuffix(hostname, suffix) {
			return zone
		}
	}

	return ""
}

// cleanZoneID removes the "/hostedzone/" prefix
func cleanZoneID(ID string) string {
	if strings.HasPrefix(ID, "/hostedzone/") {
		ID = strings.TrimPrefix(ID, "/hostedzone/")
	}
	return ID
}

func addDefaultAWSProviderSpecificAnnotations(annotations map[string]string) endpoint.ProviderSpecific {
	return addDefaultHealthCheckAnnotations(annotations)
}

// when creating health check using annotations provided on resource, AWS provide default values for
// some of the fields. Because of that now source.Record.ProviderSpecific is always different from provider.Record.ProviderSpecific
// This function adds those default values in source.Record.ProviderSpecific to make sure they are same
func addDefaultHealthCheckAnnotations(annotations map[string]string) endpoint.ProviderSpecific {
	x := getAnnotationKeyFromSuffix(providerSpecificHealthCheckFQDN)
	// log.Infof("key: %s", x)

	if _, ok := annotations[x]; !ok {
		// log.Infof("not found so returning %s", annotations)
		// This is a mandatory field when creating health check. If its not present in annotations
		// then we do not need to add the other default health check values
		return nil
	}

	props := []endpoint.ProviderSpecificProperty{}
	for _, providerSpecificKey := range []string{providerSpecificHealthCheckFailureThreshold, providerSpecificHealthCheckRequestInterval} {

		annotationKey := getAnnotationKeyFromSuffix(providerSpecificKey)
		annotationValue := annotations[annotationKey]

		switch {
		case providerSpecificKey == providerSpecificHealthCheckFailureThreshold && annotationValue == "":
			annotationValue = "3"
		case providerSpecificKey == providerSpecificHealthCheckRequestInterval && annotationValue == "":
			annotationValue = "30"
		}

		if annotationValue == "" {
			continue
		}

		// log.Infof("adding value %s for key %s", annotationValue, providerSpecificKey)

		props = append(props, endpoint.ProviderSpecificProperty{
			Name:  providerSpecificKey,
			Value: annotationValue,
		})
	}

	return props
}

func getAnnotationKeyFromSuffix(suffix string) string {
	k := strings.TrimPrefix(suffix, "aws/")
	return fmt.Sprintf("external-dns.alpha.kubernetes.io/aws-%s", k)
}

func isExternalDNSOwner(tagset map[string]string) bool {
	for tagKey := range tagset {
		if tagKey == "owner" {
			return true
		}
	}

	return false
}

func healthCheckConfigToProviderSpecific(hcConfig *route53.HealthCheckConfig, ep *endpoint.Endpoint) {
	if hcConfig.Disabled != nil && *hcConfig.Disabled {
		ep.WithProviderSpecific(providerSpecificHealthCheckDisabled, fmt.Sprintf("%t", aws.BoolValue(hcConfig.Disabled)))
	}

	if hcConfig.Port != nil {
		ep.WithProviderSpecific(providerSpecificHealthCheckPort, fmt.Sprintf("%d", aws.Int64Value(hcConfig.Port)))
	}

	if hcConfig.FailureThreshold != nil {
		ep.WithProviderSpecific(providerSpecificHealthCheckFailureThreshold, fmt.Sprintf("%d", aws.Int64Value(hcConfig.FailureThreshold)))
	}

	if hcConfig.EnableSNI != nil && *hcConfig.EnableSNI {
		ep.WithProviderSpecific(providerSpecificHealthCheckEnableSNI, fmt.Sprintf("%t", aws.BoolValue(hcConfig.EnableSNI)))
	}

	if hcConfig.FullyQualifiedDomainName != nil {
		ep.WithProviderSpecific(providerSpecificHealthCheckFQDN, aws.StringValue(hcConfig.FullyQualifiedDomainName))
	}

	if hcConfig.Inverted != nil && *hcConfig.Inverted {
		ep.WithProviderSpecific(providerSpecificHealthCheckInverted, fmt.Sprintf("%t", aws.BoolValue(hcConfig.Inverted)))
	}

	if hcConfig.RequestInterval != nil {
		ep.WithProviderSpecific(providerSpecificHealthCheckRequestInterval, fmt.Sprintf("%d", aws.Int64Value(hcConfig.RequestInterval)))
	}

	if hcConfig.ResourcePath != nil {
		ep.WithProviderSpecific(providerSpecificHealthCheckResourcePath, aws.StringValue(hcConfig.ResourcePath))
	}

	if hcConfig.Type != nil {
		ep.WithProviderSpecific(providerSpecificHealthCheckType, strings.ToUpper(aws.StringValue(hcConfig.Type)))
	}
}

func providerSpecificToHealthCheckConfig(ep *endpoint.Endpoint) *route53.HealthCheckConfig {
	hcConfig := &route53.HealthCheckConfig{}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckDisabled); ok {
		hcConfig.Disabled = aws.Bool(prop.Value == "true")
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckPort); ok {
		//TODO error check
		x, _ := strconv.Atoi(prop.Value)
		hcConfig.Port = aws.Int64(int64(x))
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckFailureThreshold); ok {
		//TODO error check
		x, _ := strconv.Atoi(prop.Value)
		hcConfig.FailureThreshold = aws.Int64(int64(x))
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckEnableSNI); ok {
		hcConfig.EnableSNI = aws.Bool(prop.Value == "true")
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckFQDN); ok {
		hcConfig.FullyQualifiedDomainName = aws.String(prop.Value)
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckInverted); ok {
		hcConfig.Inverted = aws.Bool(prop.Value == "true")
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckRequestInterval); ok {
		//TODO error check
		x, _ := strconv.Atoi(prop.Value)
		hcConfig.RequestInterval = aws.Int64(int64(x))
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckResourcePath); ok {
		hcConfig.ResourcePath = aws.String(prop.Value)
	}

	if prop, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckType); ok {
		//TODO: use enum?
		hcConfig.Type = aws.String(strings.ToUpper(prop.Value))
	}

	return hcConfig
}

func (p *AWSProvider) getHealthCheck(healthCheckID string) (*route53.HealthCheck, error) {
	input := &route53.GetHealthCheckInput{
		HealthCheckId: aws.String(healthCheckID),
	}
	output, err := p.client.GetHealthCheck(input)
	if err != nil {
		return nil, err
	}

	return output.HealthCheck, nil
}

func (p *AWSProvider) createHealthCheckIfNeeded(ep *endpoint.Endpoint) (string, error) {
	if _, ok := ep.GetProviderSpecificProperty(providerSpecificHealthCheckFQDN); !ok {
		return "", nil
	}

	hcConfig := providerSpecificToHealthCheckConfig(ep)
	log.Infof("endpoint labels when creating health check is %s for %s", ep.Labels, ep.RecordType)

	var ownerID, resource string

	if ep.RecordType == endpoint.RecordTypeTXT {
		labels, _ := endpoint.NewLabelsFromString(ep.Targets[0])
		ownerID = labels[endpoint.OwnerLabelKey]
		resource = labels[endpoint.ResourceLabelKey]
	} else {
		ownerID = ep.Labels[endpoint.OwnerLabelKey]
		resource = ep.Labels[endpoint.ResourceLabelKey]
	}

	healthCheckID, exists := p.healthCheckExists(ownerID, resource)
	if exists {
		log.Infof("health check %q already exists for owner %q", healthCheckID, ownerID)
		return healthCheckID, nil
	}

	createHCRequestInput := &route53.CreateHealthCheckInput{
		HealthCheckConfig: hcConfig,
		//CallerReference can *never* be used again. so we can't use owner string or any predictable uuid
		CallerReference: aws.String(time.Now().String()),
	}

	log.Infof("desired change to create health check %s", createHCRequestInput)
	if p.dryRun {
		return "", nil
	}

	output, err := p.client.CreateHealthCheck(createHCRequestInput)
	if err != nil {
		return "", err
	}

	if len(ep.Labels) == 0 {
		return aws.StringValue(output.HealthCheck.Id), nil
	}

	tagRequest := &route53.ChangeTagsForResourceInput{
		ResourceId:   output.HealthCheck.Id,
		ResourceType: aws.String(route53.TagResourceTypeHealthcheck),
		AddTags: []*route53.Tag{
			{
				Key:   aws.String("owner"),
				Value: aws.String(ep.Labels["owner"]),
			},
			{
				Key:   aws.String("resource"),
				Value: aws.String(ep.Labels["resource"]),
			},
		},
	}

	tagRequestOutput, err := p.client.ChangeTagsForResource(tagRequest)
	if err != nil {
		//TODO (rjindal): how should we handle this failure?
		return "", err
	}

	p.healthChecks = append(p.healthChecks, healthCheck{
		HealthCheck: output.HealthCheck,
		Tags: map[string]string{
			"owner":    ep.Labels["owner"],
			"resource": ep.Labels["resource"],
		},
	})

	log.Infof("output of creation of health check %s with tags o/p %s", output.HealthCheck, tagRequestOutput)
	return aws.StringValue(output.HealthCheck.Id), nil
}

type healthCheck struct {
	HealthCheck *route53.HealthCheck
	Tags        map[string]string
}

func (p *AWSProvider) updateHealthChecksCache() error {
	input := &route53.ListHealthChecksInput{}

	healthChecks := []healthCheck{}
	var response *route53.ListHealthChecksOutput
	var err error
	for {
		if response != nil && !aws.BoolValue(response.IsTruncated) {
			break
		}

		if response != nil {
			input.Marker = response.NextMarker
		}

		response, err = p.client.ListHealthChecks(input)
		if err != nil {
			return err
		}

		for _, hc := range response.HealthChecks {
			tags, err := p.tagsForHealthCheck(aws.StringValue(hc.Id))
			if err != nil {
				return err
			}

			healthChecks = append(healthChecks, healthCheck{
				HealthCheck: hc,
				Tags:        tags,
			})
		}
	}

	return nil
}

func (p *AWSProvider) healthCheckExists(ownerID, resource string) (string, bool) {
	for _, hc := range p.healthChecks {
		if value, ok := hc.Tags[endpoint.OwnerLabelKey]; !ok || value != ownerID {
			return "", false
		}

		if value, ok := hc.Tags[endpoint.ResourceLabelKey]; !ok || value != resource {
			return "", false
		}

		return aws.StringValue(hc.HealthCheck.Id), true
	}

	return "", false
}
