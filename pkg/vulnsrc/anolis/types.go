package anolis

// Root represents the root structure of the JSON
type AnolisCVE struct {
	Document        Document        `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Document struct {
	AggregateSeverity AggregateSeverity `json:"aggregate_severity"`
	Category          string            `json:"category"`
	CsafVersion       string            `json:"csaf_version"`
	Distribution      Distribution      `json:"distribution"`
	Lang              string            `json:"lang"`
	Notes             []Note            `json:"notes"`
	Publisher         Publisher         `json:"publisher"`
	References        []Reference       `json:"references"`
	Title             string            `json:"title"`
	Tracking          Tracking          `json:"tracking"`
}

type AggregateSeverity struct {
	Namespace string `json:"namespace"`
	Text      string `json:"text"`
}

type Distribution struct {
	Text string `json:"text"`
	TLP  TLP    `json:"tlp"`
}

type TLP struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

type Publisher struct {
	Category         string `json:"category"`
	ContactDetails   string `json:"contact_details"`
	IssuingAuthority string `json:"issuing_authority"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
}

type Reference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type Tracking struct {
	CurrentReleaseDate string     `json:"current_release_date"`
	ID                 string     `json:"id"`
	InitialReleaseDate string     `json:"initial_release_date"`
	RevisionHistory    []Revision `json:"revision_history"`
}

type Revision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type ProductTree struct {
	Branches      []Branch       `json:"branches"`
	Relationships []Relationship `json:"relationships"`
}

type Branch struct {
	Branches SubBranch `json:"branches,omitempty"`
	Category string    `json:"category"`
	Name     string    `json:"name"`
}

type SubBranch struct {
	Branches []ProductBranch `json:"branches,omitempty"`
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Product  Product         `json:"product,omitempty"`
}

type ProductBranch struct {
	Category string  `json:"category"`
	Name     string  `json:"name"`
	Product  Product `json:"product"`
}

type Product struct {
	Name                        string                      `json:"name"`
	ProductID                   string                      `json:"product_id"`
	ProductIdentificationHelper ProductIdentificationHelper `json:"product_identification_helper"`
}

type ProductIdentificationHelper struct {
	CPE string `json:"cpe"`
}

type Relationship struct {
	Category                  string          `json:"category"`
	FullProductName           FullProductName `json:"full_product_name"`
	ProductReference          string          `json:"product_reference"`
	RelatesToProductReference string          `json:"relates_to_product_reference"`
}

type FullProductName struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
}

type Vulnerability struct {
	CVE           string        `json:"cve"`
	IDs           []ID          `json:"ids"`
	Notes         []Note        `json:"notes"`
	ProductStatus ProductStatus `json:"product_status"`
	References    []Reference   `json:"references"`
	Remediations  []Remediation `json:"remediations"`
	Scores        []Score       `json:"scores"`
	Threats       []Threat      `json:"threats"`
	Title         string        `json:"title"`
}

type ID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type ProductStatus struct {
	KnownAffected []string `json:"known_affected"`
}

type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type Score struct {
	CVSSV3   CVSSV3   `json:"cvss_v3"`
	Products []string `json:"products"`
}

type CVSSV3 struct {
	AttackComplexity      string  `json:"attackComplexity"`
	AttackVector          string  `json:"attackVector"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	Scope                 string  `json:"scope"`
	UserInteraction       string  `json:"userInteraction"`
	VectorString          string  `json:"vectorString"`
	Version               string  `json:"version"`
}

type Threat struct {
	Category string `json:"category"`
	Date     string `json:"date"`
	Details  string `json:"details"`
}
