package anolis

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	layout := "2006-01-02 15:04:05"
	publishedDate, err := time.Parse(layout, "2024-05-15 11:28:31")
	if err != nil {

	}
	lastModifiedDate, err := time.Parse(layout, "2024-05-15 11:30:09")
	if err != nil {

	}
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy1",
			dir:  filepath.Join("testdata", "happy1"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2024-4810", "anolis"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3:  5.3,
						CvssVectorV3: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:N/A:H",
						Severity:     types.SeverityMedium,
						References: []string{
							"category: self,summary: CVE-2024-4810,url: https://anas.openanolis.cn/cves/detail/CVE-2024-4810", "category: external,summary: OpenAnolis Security Ratings,url: https://openanolis.cn/sig/SIG-Infra/doc/1014149186600348472", "category: external,summary: OABZ#9032,url: https://bugzilla.openanolis.cn/show_bug.cgi?id=9032", "category: self,summary: CVE-2024-4810 vex file,url: https://anas.openanolis.cn/data/csaf/cve/CVE-2024-4810.json",
						},
						Title:            "OpenAnolis cve CVE-2024-4810",
						Description:      "In register_device, the return value of ida_simple_get is unchecked,\nin witch ida_simple_get will use an invalid index value.\n\nTo address this issue, index should be checked after ida_simple_get. When\nthe index value is abnormal, a warning message should be printed, the port\nshould be dropped, and the value should be recorded.",
						PublishedDate:    &publishedDate,
						LastModifiedDate: &lastModifiedDate,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2024-4810"},
					Value: map[string]interface{}{},
				},
			},
		},
		/*{
			name: "happy2: AffectedRelease is an object",
			dir:  filepath.Join("testdata", "happy2"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2018-6044", "redhat"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3:  4.3,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
						Severity:     types.SeverityLow,
						References: []string{
							"\nhttps://chromereleases.googleblog.com/2018/07/stable-channel-update-for-desktop.html\n    ",
							"https://access.redhat.com/security/cve/CVE-2018-6044",
						},
						Title:       "chromium-browser: Request privilege escalation in Extensions",
						Description: "** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-6044"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy3: PackageState is an array",
			dir:  filepath.Join("testdata", "happy3"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2019-8559", "redhat"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3:  6.3,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
						Severity:     types.SeverityMedium,
						References: []string{
							"https://access.redhat.com/security/cve/CVE-2019-8559",
						},
						Title:       "webkitgtk: malicious web content leads to arbitrary code execution",
						Description: "No description is available for this CVE.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-8559"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy4: PackageState is an object",
			dir:  filepath.Join("testdata", "happy4"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2004-2680", "redhat"},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityLow,
						References: []string{
							"https://access.redhat.com/security/cve/CVE-2004-2680",
						},
						Title:       "mod_python arbitrary data disclosure flaw",
						Description: "mod_python (libapache2-mod-python) 3.1.4 and earlier does not properly handle when output filters process more than 16384 bytes, which can cause filter.read to return portions of previously freed memory.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2004-2680"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy5: PackageName is empty",
			dir:  filepath.Join("testdata", "happy5"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2019-0160", "redhat"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3:  5.9,
						CvssVectorV3: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
						Severity:     types.SeverityCritical,
						References: []string{
							"https://access.redhat.com/security/cve/CVE-2019-0160",
						},
						Title:       "edk2: Buffer overflows in PartitionDxe and UdfDxe with long file names and invalid UDF media",
						Description: "Buffer overflow in system firmware for EDK II may allow unauthenticated user to potentially enable escalation of privilege and/or denial of service via network access.\n    \nBuffer overflows were discovered in UDF-related codes under MdeModulePkg\\Universal\\Disk\\PartitionDxe\\Udf.c and MdeModulePkg\\Universal\\Disk\\UdfDxe, which could be triggered with long file names or invalid formatted UDF media.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-0160"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy6: unknown platform",
			dir:  filepath.Join("testdata", "happy6"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2019-8559", "redhat"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3:  6.3,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
						Severity:     types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/security/cve/CVE-2019-8559",
						},
						Title:       "webkitgtk: malicious web content leads to arbitrary code execution",
						Description: "No description is available for this CVE.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-8559"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy7: unknown status",
			dir:  filepath.Join("testdata", "happy7"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2019-8559", "redhat"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3:  6.3,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
						Severity:     types.SeverityUnknown,
						References: []string{
							"https://access.redhat.com/security/cve/CVE-2019-8559",
						},
						Title:       "webkitgtk: malicious web content leads to arbitrary code execution",
						Description: "No description is available for this CVE.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-8559"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad1: AffectedRelease is an invalid array",
			dir:     filepath.Join("testdata", "sad1"),
			wantErr: "json: cannot unmarshal string into Go struct field RedhatCVEAffectedReleaseArray.affected_release of type redhat.RedhatAffectedRelease",
		},
		{
			name:    "sad2: AffectedRelease is an invalid object",
			dir:     filepath.Join("testdata", "sad2"),
			wantErr: "json: cannot unmarshal number into Go struct field RedhatAffectedRelease.affected_release.product_name of type string",
		},
		{
			name:    "sad3: PackageState is an invalid array",
			dir:     filepath.Join("testdata", "sad3"),
			wantErr: "json: cannot unmarshal string into Go struct field RedhatCVEPackageStateArray.package_state of type redhat.RedhatPackageState",
		},
		{
			name:    "sad4: PackageState is an invalid object",
			dir:     filepath.Join("testdata", "sad4"),
			wantErr: "json: cannot unmarshal number into Go struct field RedhatPackageState.package_state.product_name of type string",
		},
		{
			name:    "sad5: invalid JSON",
			dir:     filepath.Join("testdata", "sad5"),
			wantErr: "json: cannot unmarshal string into Go value of type redhat.RedhatCVE",
		},
		{
			name:    "sad6: AffectedRelease is an unknown type",
			dir:     filepath.Join("testdata", "sad6"),
			wantErr: "unknown affected_release type",
		},
		{
			name:    "sad7: PackageState is an unknown type",
			dir:     filepath.Join("testdata", "sad7"),
			wantErr: "unknown package_state type",
		},
		{
			name:    "sad8: failed to decode",
			dir:     filepath.Join("testdata", "sad8"),
			wantErr: "failed to decode RedHat JSON",
		},
		{
			name:    "sad9: dir doesn't exist",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "no such file or directory",
		},*/
		{
			name:    "sad1: invalid JSON",
			dir:     filepath.Join("testdata", "sad1"),
			wantErr: "json: cannot unmarshal string into Go value of type anolis.AnolisCVE",
		},
		{
			name:    "sad2: failed to decode",
			dir:     filepath.Join("testdata", "sad2"),
			wantErr: "failed to decode Anolis JSON",
		},
		{
			name:    "sad3: dir doesn't exist",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "cannot find the path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
