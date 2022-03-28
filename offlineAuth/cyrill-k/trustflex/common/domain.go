// domain related functions

package common

import (
	"log"
	"regexp"
	"strings"
)

const (
	MaxDomainLength = 255
)

var (
	viableDomain   *regexp.Regexp
	wildcardDomain *regexp.Regexp
	incorrectLabel *regexp.Regexp
	correctLabel   *regexp.Regexp
)

func init() {
	var err error
	wildcardDomain, err = regexp.Compile("^\\*\\..*$")
	LogError("Couldn't compile wildcard domain regexp: %s", err)
	// todo(cyrill) also perform other checks except the wildcard check (e.g., only allowed characters)
	viableDomain, err = regexp.Compile("^(\\*\\.)?[^*]*$")
	LogError("Couldn't compile viable domain regexp: %s", err)

	incorrectLabel, err = regexp.Compile("^[[:digit:]]*$")
	// correctLabel, err = regexp.Compile("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$")
	LogError("Couldn't compile incorrect label regexp: %s", err)

	correctLabel, err = regexp.Compile("^(\\*|[[:alnum:]]|[[:alnum:]][[:alnum:]-]{0,61}[[:alnum:]])$")
	// correctLabel, err = regexp.Compile("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$")
	LogError("Couldn't compile correct label regexp: %s", err)
}

func IsDomainContainedIn(domain, parentDomain string) bool {
	if strings.HasSuffix("."+domain, "."+parentDomain) {
		return true
	}
	if IsWildcardDomain(parentDomain) {
		domainShort, err := SplitE2LD(domain)
		if err != nil {
			log.Printf("Cannot split %s into E2LD and subdomains: %s", domain, err)
			return false
		}
		parentDomainShort, err := SplitE2LD(parentDomain)
		if err != nil {
			log.Printf("Cannot split %s into E2LD and subdomains: %s", parentDomain, err)
			return false
		}
		if len(domainShort) > 1 && len(parentDomainShort) > 1 && strings.HasSuffix("."+strings.Join(domainShort[1:], "."), "."+strings.Join(parentDomainShort[1:], ".")) {
			return true
		}
		// domainShort := strings.Join(SplitE2LD(domain), ".")
		// parentShort := strings.Join(SplitE2LD(parentDomain), ".")
		// if len(domainShort) > 1 && len(parentShort) > 1 && strings.HasSuffix(domainShort[1:], "."+parentShort[1:]) {
		// 	return true
		// }
	}
	return false
}

func IsSameDomain(domain1, domain2 string) bool {
	if domain1 == domain2 {
		return true
	}
	if IsWildcardDomain(domain1) || IsWildcardDomain(domain2) {
		domain1Short, err := SplitE2LD(domain1)
		if err != nil {
			log.Printf("Cannot split %s into E2LD and subdomains: %s", domain1, err)
			return false
		}
		domain2Short, err := SplitE2LD(domain2)
		if err != nil {
			log.Printf("Cannot split %s into E2LD and subdomains: %s", domain2, err)
			return false
		}
		if len(domain1Short) > 1 && len(domain2Short) > 1 && strings.Join(domain1Short[1:], ".") == strings.Join(domain2Short[1:], ".") {
			return true
		}
	}
	return false
}

// only allow wildcards for the deepest subdomain
func IsViableDomain(domain string) bool {
	// removes domains with wildcard labels other than the first label
	if !viableDomain.Match([]byte(domain)) {
		return false
	}
	// remove long domains
	if len(domain) > MaxDomainLength {
		return false
	}
	for _, n := range strings.Split(domain, ".") {
		// remove numeric labels
		if incorrectLabel.Match([]byte(n)) {
			return false
		}
		// remove invalid characters and hyphens at the beginning and end
		if !correctLabel.Match([]byte(n)) {
			return false
		}
	}
	return true
}

// is the deepest subdomain a wildcard domain
func IsWildcardDomain(domain string) bool {
	return wildcardDomain.Match([]byte(domain))
}

func IsE2LD(domain string) bool {
	labels, err := SplitE2LD(domain)
	return err == nil && len(labels) == 1
}

func SplitE2LD(domain string) ([]string, error) {
	//if !IsViableDomain(domain) {
	//	return nil, fmt.Errorf("'%s' is not a viable domain", domain)
	//}
	//u, err := url.Parse("http://" + domain)
	//if err != nil {
	//	return nil, fmt.Errorf("Couldn't parse url '%s': %s", domain, err)
	//}
	//if u.Hostname() != domain {
	//	return nil, fmt.Errorf("input contains non-domain related characters: '%s' != '%s'", domain, u.Hostname())
	//}
	//_, hasPublicSuffix := publicsuffix.PublicSuffix(domain)
	//if !hasPublicSuffix {
	//	return nil, fmt.Errorf("'%s' does not have a public suffix", domain)
	//}
	//e2LD, err := publicsuffix.EffectiveTLDPlusOne(domain)
	//if err != nil {
	//	return []string{domain}, nil
	//	return nil, fmt.Errorf("couldn't extract e2LD of '%s': %s", domain, err)
	//}
	//domain = strings.TrimSuffix(domain, e2LD)
	//domain = strings.TrimSuffix(domain, ".")
	//var subdomains []string
	//if domain != "" {
	//	subdomains = strings.Split(domain, ".")
	//}
	//subdomains = append(subdomains, e2LD)
	//return subdomains, nil
	return []string{domain}, nil
}

func IsWildcardLabel(label string) bool {
	return label == "*"
}
