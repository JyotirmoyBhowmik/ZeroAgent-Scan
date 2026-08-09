package vulnscan

import (
	"strconv"
	"strings"
)

// MatchesCPE checks if a candidate host CPE satisfies an NVD CVE match criteria.
func MatchesCPE(hostCPE CPE23, criteria NVDCpeMatch) bool {
	if !criteria.Vulnerable && criteria.Criteria == "" {
		return false
	}

	critCPE, err := ParseCPE23String(criteria.Criteria)
	if err != nil {
		// Fallback: simple substring check
		if strings.Contains(strings.ToLower(criteria.Criteria), hostCPE.Product) {
			return checkVersionBounds(hostCPE.Version, criteria)
		}
		return false
	}

	// 1. Check Part (e.g. "a", "o", "h")
	if critCPE.Part != "*" && hostCPE.Part != "*" && critCPE.Part != hostCPE.Part {
		return false
	}

	// 2. Check Vendor
	if critCPE.Vendor != "*" && hostCPE.Vendor != "*" {
		if !strings.EqualFold(critCPE.Vendor, hostCPE.Vendor) &&
			!strings.Contains(strings.ToLower(hostCPE.Vendor), strings.ToLower(critCPE.Vendor)) &&
			!strings.Contains(strings.ToLower(critCPE.Vendor), strings.ToLower(hostCPE.Vendor)) {
			return false
		}
	}

	// 3. Check Product
	if critCPE.Product != "*" && hostCPE.Product != "*" {
		if !strings.EqualFold(critCPE.Product, hostCPE.Product) &&
			!strings.Contains(strings.ToLower(hostCPE.Product), strings.ToLower(critCPE.Product)) &&
			!strings.Contains(strings.ToLower(critCPE.Product), strings.ToLower(hostCPE.Product)) {
			return false
		}
	}

	// 4. Check Version Range & Exact Match
	return checkVersionBounds(hostCPE.Version, criteria)
}

func checkVersionBounds(hostVer string, criteria NVDCpeMatch) bool {
	if hostVer == "" || hostVer == "*" {
		return true
	}

	// If explicit range bounds exist
	hasRange := criteria.VersionStartIncluding != "" ||
		criteria.VersionStartExcluding != "" ||
		criteria.VersionEndIncluding != "" ||
		criteria.VersionEndExcluding != ""

	if hasRange {
		if criteria.VersionStartIncluding != "" {
			if CompareVersions(hostVer, criteria.VersionStartIncluding) < 0 {
				return false
			}
		}
		if criteria.VersionStartExcluding != "" {
			if CompareVersions(hostVer, criteria.VersionStartExcluding) <= 0 {
				return false
			}
		}
		if criteria.VersionEndIncluding != "" {
			if CompareVersions(hostVer, criteria.VersionEndIncluding) > 0 {
				return false
			}
		}
		if criteria.VersionEndExcluding != "" {
			if CompareVersions(hostVer, criteria.VersionEndExcluding) >= 0 {
				return false
			}
		}
		return true
	}

	// Exact version check from Criteria string
	critCPE, err := ParseCPE23String(criteria.Criteria)
	if err == nil {
		if critCPE.Version == "*" || critCPE.Version == "-" {
			return true
		}
		return CompareVersions(hostVer, critCPE.Version) == 0 || strings.EqualFold(hostVer, critCPE.Version)
	}

	return true
}

// ParseCPE23String parses a standard CPE 2.3 string into CPE23 components.
func ParseCPE23String(cpeStr string) (CPE23, error) {
	parts := strings.Split(cpeStr, ":")
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return CPE23{}, strconv.ErrSyntax
	}

	res := CPE23{
		Part:    parts[2],
		Vendor:  parts[3],
		Product: parts[4],
	}
	if len(parts) > 5 {
		res.Version = parts[5]
	}
	if len(parts) > 6 {
		res.Update = parts[6]
	}
	if len(parts) > 7 {
		res.Edition = parts[7]
	}
	if len(parts) > 8 {
		res.Language = parts[8]
	}
	if len(parts) > 9 {
		res.SwEdition = parts[9]
	}
	if len(parts) > 10 {
		res.TargetSw = parts[10]
	}
	if len(parts) > 11 {
		res.TargetHw = parts[11]
	}
	if len(parts) > 12 {
		res.Other = parts[12]
	}

	return res, nil
}

// CompareVersions compares two version strings lexicographically / numerically.
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	v1Clean := strings.TrimPrefix(strings.TrimSpace(v1), "v")
	v2Clean := strings.TrimPrefix(strings.TrimSpace(v2), "v")

	if v1Clean == v2Clean {
		return 0
	}

	parts1 := strings.Split(v1Clean, ".")
	parts2 := strings.Split(v2Clean, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int64
		var err1, err2 error

		if i < len(parts1) {
			n1, err1 = strconv.ParseInt(cleanNumber(parts1[i]), 10, 64)
		}
		if i < len(parts2) {
			n2, err2 = strconv.ParseInt(cleanNumber(parts2[i]), 10, 64)
		}

		// If both are numbers, compare numerically
		if err1 == nil && err2 == nil {
			if n1 < n2 {
				return -1
			}
			if n1 > n2 {
				return 1
			}
		} else {
			// String comparison fallback
			s1, s2 := "", ""
			if i < len(parts1) {
				s1 = parts1[i]
			}
			if i < len(parts2) {
				s2 = parts2[i]
			}
			if s1 < s2 {
				return -1
			}
			if s1 > s2 {
				return 1
			}
		}
	}

	return 0
}

func cleanNumber(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		} else {
			break
		}
	}
	return sb.String()
}
