package anolis

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	vulnListDir = "vuln-list-anolis"
	apiDir      = "api"

	resourceURL = "https://anas.openanolis.cn/cves/detail/%s"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.Anolis
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, vulnListDir, apiDir)

	var cves []AnolisCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		content, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		cve := AnolisCVE{}
		if err = json.Unmarshal(content, &cve); err != nil {
			return xerrors.Errorf("failed to decode Anolis JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Anolis walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Anolis save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []AnolisCVE) error {
	log.Println("Saving Anolis DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []AnolisCVE) error {
	for _, cve := range cves {
		if err := vs.putVulnerabilityDetail(tx, cve); err != nil {
			return err
		}
	}

	return nil
}

func (vs VulnSrc) putVulnerabilityDetail(tx *bolt.Tx, cve AnolisCVE) error {
	var CVESore Score = cve.Vulnerabilities[0].Scores[0]

	var references []string
	for _, ref := range cve.Document.References {
		formattedStr := fmt.Sprintf("category: %s,summary: %s,url: %s", ref.Category, ref.Summary, ref.URL)
		references = append(references, formattedStr)
	}

	layout := "2006-01-02 15:04:05"
	publishedDate, err := time.Parse(layout, cve.Document.Tracking.InitialReleaseDate)
	if err != nil {
		return err
	}
	lastModifiedDate, err := time.Parse(layout, cve.Document.Tracking.CurrentReleaseDate)
	if err != nil {
		return err
	}

	vuln := types.VulnerabilityDetail{
		CvssScoreV3:      CVESore.CVSSV3.BaseScore,
		CvssVectorV3:     CVESore.CVSSV3.VectorString,
		Severity:         severityFromThreat(cve.Document.AggregateSeverity.Text),
		References:       references,
		Title:            strings.TrimSpace(cve.Document.Title),
		Description:      strings.TrimSpace(cve.Document.Notes[1].Text),
		PublishedDate:    &publishedDate,
		LastModifiedDate: &lastModifiedDate,
	}
	if err := vs.dbc.PutVulnerabilityDetail(tx, cve.Document.Tracking.ID, vulnerability.Anolis, vuln); err != nil {
		return xerrors.Errorf("failed to save Anolis vulnerability: %w", err)
	}

	// for optimization
	if err := vs.dbc.PutVulnerabilityID(tx, cve.Document.Tracking.ID); err != nil {
		return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
	}
	return nil
}

func severityFromThreat(sev string) types.Severity {
	severity := cases.Title(language.English).String(sev)
	switch severity {
	case "Low":
		return types.SeverityLow
	case "Moderate":
		return types.SeverityMedium
	case "Important":
		return types.SeverityHigh
	case "Critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
