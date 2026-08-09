package vulnscan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
)

var (
	nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9_\.\-]`)
	multipleUnderscores  = regexp.MustCompile(`_+`)
	versionExtractRegex  = regexp.MustCompile(`^v?(\d+(\.\d+)*)`)
)

// CPE23 represents a parsed or constructed Common Platform Enumeration 2.3 identifier.
type CPE23 struct {
	Part       string // "a" (application), "o" (operating system), "h" (hardware)
	Vendor     string
	Product    string
	Version    string
	Update     string
	Edition    string
	Language   string
	SwEdition  string
	TargetSw   string
	TargetHw   string
	Other      string
	RawApp     string
	AppVersion string
}

// String formats the CPE into standard CPE 2.3 URI:
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
func (c CPE23) String() string {
	part := c.Part
	if part == "" {
		part = "a"
	}
	vendor := sanitizeCPEField(c.Vendor)
	if vendor == "" {
		vendor = "*"
	}
	product := sanitizeCPEField(c.Product)
	if product == "" {
		product = "*"
	}
	version := sanitizeCPEField(c.Version)
	if version == "" {
		version = "*"
	}
	update := sanitizeCPEField(c.Update)
	if update == "" {
		update = "*"
	}
	edition := sanitizeCPEField(c.Edition)
	if edition == "" {
		edition = "*"
	}
	lang := sanitizeCPEField(c.Language)
	if lang == "" {
		lang = "*"
	}
	swEdition := sanitizeCPEField(c.SwEdition)
	if swEdition == "" {
		swEdition = "*"
	}
	targetSw := sanitizeCPEField(c.TargetSw)
	if targetSw == "" {
		targetSw = "*"
	}
	targetHw := sanitizeCPEField(c.TargetHw)
	if targetHw == "" {
		targetHw = "*"
	}
	other := sanitizeCPEField(c.Other)
	if other == "" {
		other = "*"
	}

	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		part, vendor, product, version, update, edition, lang, swEdition, targetSw, targetHw, other)
}

// BuildCPEFromApp translates an installed Windows application into a CPE 2.3 structure.
func BuildCPEFromApp(app models.SnapshotApplicationEntry) CPE23 {
	vendor := normalizeVendor(app.Publisher, app.Name)
	product := normalizeProduct(app.Name)
	version := normalizeVersion(app.Version)

	targetHw := "*"
	if app.Architecture != nil {
		arch := strings.ToLower(*app.Architecture)
		if strings.Contains(arch, "64") {
			targetHw = "x64"
		} else if strings.Contains(arch, "86") || strings.Contains(arch, "32") {
			targetHw = "x86"
		}
	}

	return CPE23{
		Part:       "a",
		Vendor:     vendor,
		Product:    product,
		Version:    version,
		TargetSw:   "windows",
		TargetHw:   targetHw,
		RawApp:     app.Name,
		AppVersion: version,
	}
}

// BuildCPEFromOS translates the host OS identity into an OS CPE 2.3 structure.
func BuildCPEFromOS(osName, osVersion, osBuild string) CPE23 {
	product := "windows"
	version := osVersion
	update := "*"

	lowOS := strings.ToLower(osName)
	if strings.Contains(lowOS, "windows 11") {
		product = "windows_11"
		if strings.Contains(lowOS, "23h2") {
			update = "23h2"
		} else if strings.Contains(lowOS, "22h2") {
			update = "22h2"
		}
	} else if strings.Contains(lowOS, "windows 10") {
		product = "windows_10"
	} else if strings.Contains(lowOS, "server 2022") {
		product = "windows_server_2022"
	} else if strings.Contains(lowOS, "server 2025") {
		product = "windows_server_2025"
	} else if strings.Contains(lowOS, "server 2019") {
		product = "windows_server_2019"
	}

	if version == "" && osBuild != "" {
		version = osBuild
	}

	return CPE23{
		Part:       "o",
		Vendor:     "microsoft",
		Product:    product,
		Version:    normalizeVersion(&version),
		Update:     update,
		TargetSw:   "*",
		TargetHw:   "x64",
		RawApp:     osName,
		AppVersion: version,
	}
}

// ExtractHostCPEs extracts a complete list of candidate CPEs from a host snapshot.
func ExtractHostCPEs(snapshot *models.HostSnapshotPayload) []CPE23 {
	if snapshot == nil {
		return nil
	}

	var cpes []CPE23

	// 1. Operating System CPE
	osCPE := BuildCPEFromOS(snapshot.SystemIdentity.OSName, snapshot.SystemIdentity.OSVersion, snapshot.SystemIdentity.OSBuild)
	cpes = append(cpes, osCPE)

	// 2. Installed Software CPEs
	for _, app := range snapshot.Software.Applications {
		if strings.TrimSpace(app.Name) == "" {
			continue
		}
		cpe := BuildCPEFromApp(app)
		cpes = append(cpes, cpe)
	}

	return cpes
}

// ---------------------------------------------------------------------------
// Normalization Helpers
// ---------------------------------------------------------------------------

func normalizeVendor(publisher *string, appName string) string {
	pub := ""
	if publisher != nil {
		pub = strings.ToLower(strings.TrimSpace(*publisher))
	}
	appLow := strings.ToLower(appName)

	if strings.Contains(pub, "google") || strings.Contains(appLow, "google chrome") {
		return "google"
	}
	if strings.Contains(pub, "microsoft") || strings.Contains(appLow, "microsoft edge") || strings.Contains(appLow, "visual studio") {
		return "microsoft"
	}
	if strings.Contains(pub, "mozilla") || strings.Contains(appLow, "firefox") {
		return "mozilla"
	}
	if strings.Contains(pub, "adobe") || strings.Contains(appLow, "acrobat") || strings.Contains(appLow, "photoshop") {
		return "adobe"
	}
	if strings.Contains(pub, "oracle") || strings.Contains(appLow, "java") || strings.Contains(appLow, "virtualbox") {
		return "oracle"
	}
	if strings.Contains(pub, "cisco") || strings.Contains(appLow, "anyconnect") {
		return "cisco"
	}
	if strings.Contains(pub, "docker") || strings.Contains(appLow, "docker desktop") {
		return "docker"
	}
	if strings.Contains(pub, "python") || strings.Contains(appLow, "python 3") {
		return "python"
	}
	if strings.Contains(pub, "7-zip") || strings.Contains(appLow, "7-zip") {
		return "7-zip"
	}
	if strings.Contains(pub, "wireshark") || strings.Contains(appLow, "wireshark") {
		return "wireshark"
	}
	if strings.Contains(pub, "notepad++") || strings.Contains(appLow, "notepad++") {
		return "notepad-plus-plus"
	}

	if pub != "" {
		cleaned := sanitizeCPEField(pub)
		if cleaned != "" {
			return cleaned
		}
	}

	// Fallback to first word of app name
	parts := strings.Fields(appName)
	if len(parts) > 0 {
		return sanitizeCPEField(parts[0])
	}

	return "unknown"
}

func normalizeProduct(appName string) string {
	appLow := strings.ToLower(strings.TrimSpace(appName))

	if strings.Contains(appLow, "google chrome") || appLow == "chrome" {
		return "chrome"
	}
	if strings.Contains(appLow, "microsoft edge") || appLow == "edge" {
		return "edge"
	}
	if strings.Contains(appLow, "mozilla firefox") || appLow == "firefox" {
		return "firefox"
	}
	if strings.Contains(appLow, "adobe acrobat reader") || strings.Contains(appLow, "acrobat reader") {
		return "acrobat_reader"
	}
	if strings.Contains(appLow, "7-zip") {
		return "7-zip"
	}
	if strings.Contains(appLow, "wireshark") {
		return "wireshark"
	}
	if strings.Contains(appLow, "notepad++") {
		return "notepad\\+\\+"
	}
	if strings.Contains(appLow, "docker desktop") {
		return "docker_desktop"
	}
	if strings.Contains(appLow, "python") {
		return "python"
	}
	if strings.Contains(appLow, "vlc media player") || strings.Contains(appLow, "vlc") {
		return "vlc_media_player"
	}
	if strings.Contains(appLow, "git") {
		return "git"
	}

	cleaned := sanitizeCPEField(appLow)
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

func normalizeVersion(ver *string) string {
	if ver == nil || strings.TrimSpace(*ver) == "" {
		return "*"
	}

	v := strings.TrimSpace(*ver)
	// Match leading numeric version pattern (e.g. "124.0.6367.208" or "v2.4.1")
	match := versionExtractRegex.FindStringSubmatch(v)
	if len(match) > 1 && match[1] != "" {
		return match[1]
	}

	return sanitizeCPEField(v)
}

func sanitizeCPEField(val string) string {
	v := strings.ToLower(strings.TrimSpace(val))
	v = strings.ReplaceAll(v, " ", "_")
	v = nonAlphanumericRegex.ReplaceAllString(v, "")
	v = multipleUnderscores.ReplaceAllString(v, "_")
	return strings.Trim(v, "_")
}
