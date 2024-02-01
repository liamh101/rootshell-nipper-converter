package main

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"fmt"
	"io"
	"os"
	"strings"
)

type Device struct {
	DeviceUrl string `xml:"device_url,attr"`
	Name      string `xml:"name,attr"`
}

type Content struct {
	Ordered  *int   `xml:"ordered,attr"`
	Seq      int    `xml:"seq,attr"`
	Type     string `xml:"type,attr"`
	CharData string `xml:",chardata"`
	Headings *struct {
		Header []struct {
			Seq      int    `xml:"seq,attr"`
			CharData string `xml:",chardata"`
		} `xml:"header"`
	} `xml:"headings"`
	ListItem []struct {
		Seq int `xml:"seq,attr"`
	} `xml:"list-item"`
	Rows *struct {
		Row []struct {
			Seq  int `xml:"seq,attr"`
			Cell []struct {
				Seq      int `xml:"seq,attr"`
				CellItem []struct {
					Seq      int    `xml:"seq,attr"`
					CharData string `xml:",chardata"`
				} `xml:"cell-item"`
			} `xml:"cell"`
		} `xml:"row"`
	} `xml:"rows"`
	Title *string `xml:"title"`
}

type Report struct {
	Devices struct {
		Device []struct {
			Description string `xml:"description,attr"`
			DeviceUrl   string `xml:"device_url,attr"`
			Name        string `xml:"name,attr"`
			Os          string `xml:"os,attr"`
			Version     string `xml:"version,attr"`
		} `xml:"device"`
	} `xml:"devices"`
	Sections struct {
		Section []struct {
			Contents *struct {
				Content []struct {
					Ordered  *int   `xml:"ordered,attr"`
					Seq      int    `xml:"seq,attr"`
					Type     string `xml:"type,attr"`
					CharData string `xml:",chardata"`
					ListItem []struct {
						Seq int `xml:"seq,attr"`
					} `xml:"list-item"`
				} `xml:"content"`
			} `xml:"contents"`
			ExtraInfo *struct {
				AUDIT string `xml:"AUDIT"`
			} `xml:"extra-info"`
			Subsections struct {
				Section []struct {
					Seq      int `xml:"seq,attr"`
					Contents *struct {
						Content []Content `xml:"content"`
					} `xml:"contents"`
					Cvssv31 *struct {
						BaseMetrics struct {
							AttackComplexity      string  `xml:"attack-complexity"`
							AttackVector          string  `xml:"attack-vector"`
							AvailabilityImpact    string  `xml:"availability-impact"`
							BaseScore             float64 `xml:"base-score"`
							BaseSeverity          string  `xml:"base-severity"`
							ConfidentialityImpact string  `xml:"confidentiality-impact"`
							IntegrityImpact       string  `xml:"integrity-impact"`
							PrivilegesRequired    string  `xml:"privileges-required"`
							Scope                 string  `xml:"scope"`
							UserInteraction       string  `xml:"user-interaction"`
						} `xml:"base_metrics"`
						EnvironmentalMetrics struct {
							AvailabilityRequirement       string  `xml:"availability-requirement"`
							ConfidentialityRequirement    string  `xml:"confidentiality-requirement"`
							EnvironmentalScore            float64 `xml:"environmental-score"`
							EnvironmentalSeverity         string  `xml:"environmental-severity"`
							IntegrityRequirement          string  `xml:"integrity-requirement"`
							ModifiedAttackComplexity      string  `xml:"modified-attack-complexity"`
							ModifiedAttackVector          string  `xml:"modified-attack-vector"`
							ModifiedAvailabilityImpact    string  `xml:"modified-availability-impact"`
							ModifiedConfidentialityImpact string  `xml:"modified-confidentiality-impact"`
							ModifiedIntegrityImpact       string  `xml:"modified-integrity-impact"`
							ModifiedPrivilegesRequired    string  `xml:"modified-privileges-required"`
							ModifiedScope                 string  `xml:"modified-scope"`
							ModifiedUserInteraction       string  `xml:"modified-user-interaction"`
						} `xml:"environmental_metrics"`
						TemporalMetrics struct {
							ExploitCodeMaturity string  `xml:"exploit-code-maturity"`
							RemediationLevel    string  `xml:"remediation-level"`
							ReportConfidence    string  `xml:"report-confidence"`
							TemporalScore       float64 `xml:"temporal-score"`
							TemporalSeverity    string  `xml:"temporal-severity"`
						} `xml:"temporal_metrics"`
						TitaniaRating string `xml:"titaniaRating"`
					} `xml:"cvssv3.1"`
					Devices *struct {
						Device []Device `xml:"device"`
					} `xml:"devices"`
					ExtraInfo *struct {
						AUDIT          string `xml:"AUDIT"`
						CLASSIFICATION *struct {
							Item []string `xml:"item"`
						} `xml:"CLASSIFICATION"`
						CON     *string `xml:"CON"`
						FIXEDBY *string `xml:"FIXEDBY"`
						FIXES   *struct {
							Item []string `xml:"item"`
						} `xml:"FIXES"`
						REC *struct {
							Item []string `xml:"item"`
						} `xml:"REC"`
						RELATED *struct {
							Item []string `xml:"item"`
						} `xml:"RELATED"`
					} `xml:"extra-info"`
					Nipper *struct {
						Ease          string `xml:"ease"`
						Fix           string `xml:"fix"`
						Impact        string `xml:"impact"`
						Summary       string `xml:"summary"`
						TitaniaRating string `xml:"titaniaRating"`
					} `xml:"nipper"`
					Subsections *struct {
						Section []struct {
							Seq      int `xml:"seq,attr"`
							Contents *struct {
								Content []Content `xml:"content"`
							} `xml:"contents"`
							ExtraInfo *struct {
								AUDIT string `xml:"AUDIT"`
							} `xml:"extra-info"`
							Subsections *struct {
								Section []struct {
									Seq      int `xml:"seq,attr"`
									Contents struct {
										Content []struct {
											Ordered  *int   `xml:"ordered,attr"`
											Seq      int    `xml:"seq,attr"`
											Type     string `xml:"type,attr"`
											CharData string `xml:",chardata"`
											Headings *struct {
												Header []struct {
													Seq      int    `xml:"seq,attr"`
													CharData string `xml:",chardata"`
												} `xml:"header"`
											} `xml:"headings"`
											InfoItem []struct {
												Key      string `xml:"key,attr"`
												Seq      int    `xml:"seq,attr"`
												CharData string `xml:",chardata"`
											} `xml:"info-item"`
											ListItem []struct {
												Seq int `xml:"seq,attr"`
											} `xml:"list-item"`
											Rows *struct {
												Row []struct {
													Seq  int `xml:"seq,attr"`
													Cell []struct {
														Seq      int `xml:"seq,attr"`
														CellItem []struct {
															Seq      int    `xml:"seq,attr"`
															CharData string `xml:",chardata"`
														} `xml:"cell-item"`
													} `xml:"cell"`
												} `xml:"row"`
											} `xml:"rows"`
											Title *string `xml:"title"`
										} `xml:"content"`
									} `xml:"contents"`
									ExtraInfo *struct {
										AUDIT string `xml:"AUDIT"`
									} `xml:"extra-info"`
									Subsections *struct {
										Section []struct {
											Seq      int `xml:"seq,attr"`
											Contents struct {
												Content struct {
													Ordered  *int   `xml:"ordered,attr"`
													Seq      int    `xml:"seq,attr"`
													Type     string `xml:"type,attr"`
													CharData string `xml:",chardata"`
													Headings *struct {
														Header []struct {
															Seq      int    `xml:"seq,attr"`
															CharData string `xml:",chardata"`
														} `xml:"header"`
													} `xml:"headings"`
													ListItem []struct {
														Seq int `xml:"seq,attr"`
													} `xml:"list-item"`
													Rows *struct {
														Row []struct {
															Seq  int `xml:"seq,attr"`
															Cell []struct {
																Seq      int `xml:"seq,attr"`
																CellItem []struct {
																	Seq      int    `xml:"seq,attr"`
																	CharData string `xml:",chardata"`
																} `xml:"cell-item"`
															} `xml:"cell"`
														} `xml:"row"`
													} `xml:"rows"`
													Title *string `xml:"title"`
												} `xml:"content"`
											} `xml:"contents"`
											Title string `xml:"title"`
										} `xml:"section"`
									} `xml:"subsections"`
									Title string `xml:"title"`
								} `xml:"section"`
							} `xml:"subsections"`
							Title string `xml:"title"`
						} `xml:"section"`
					} `xml:"subsections"`
					Title string `xml:"title"`
				} `xml:"section"`
			} `xml:"subsections"`
			Title string `xml:"title"`
		} `xml:"section"`
	} `xml:"sections"`
}

type PrismBaseFile struct {
	Version int         `json:"version"`
	Issues  []PrismItem `json:"issues"`
}

type PrismItem struct {
	Name                    string      `json:"name"`
	OriginalRiskRating      string      `json:"original_risk_rating"`
	ClientDefinedRiskRating string      `json:"client_defined_risk_rating"`
	Finding                 string      `json:"finding"`
	Summary                 string      `json:"summary"`
	Recommendation          string      `json:"recommendation"`
	CvssVector              string      `json:"cvss_vector"`
	AffectedHosts           []PrismHost `json:"affected_hosts"`
	Cves                    []string    `json:"cves"`
	References              []string    `json:"references"`
	TechnicalDetails        string      `json:"technical_details"`
}

type PrismHost struct {
	Name string `json:"name"`
}

func main() {
	var filename = os.Args[1]
	fmt.Println("Looking for Nipper V3 File: " + filename)
	report := parseNipperFile(filename)

	if (len(report.Sections.Section) == 0) {
		fmt.Println("No contents found in report. Nipper is prown to generating invalid XML. Please check.")
	}

	fmt.Println("Generating Report")

	var prismResult PrismBaseFile
	prismResult.Version = 1

	for _, section := range report.Sections.Section {
		for _, subsections := range section.Subsections.Section {
			if subsections.Nipper != nil {
				var issue PrismItem

				issue.Name = subsections.Title
				issue.OriginalRiskRating = subsections.Nipper.Impact
				issue.ClientDefinedRiskRating = subsections.Nipper.Impact

				issue.AffectedHosts = getHosts(subsections.Devices.Device)

				for _, subSubsections := range subsections.Subsections.Section {
					if subSubsections.Title == "Finding" {
						issue.Finding = getContents(subSubsections.Contents.Content)
					}

					if subSubsections.Title == "Impact" {
						issue.Summary = getContents(subSubsections.Contents.Content)
					}

					if subSubsections.Title == "Ease" {
						issue.TechnicalDetails = getContents(subSubsections.Contents.Content)
					}

					if subSubsections.Title == "Recommendation" {
						issue.Recommendation = getContents(subSubsections.Contents.Content)
					}
				}

				// remove phrase "Nipper" from report
				issue.NipperToPrism()
				prismResult.Issues = append(prismResult.Issues, issue)
			}
		}
	}
	// Add Software Audit
	prismResult.Issues = append(prismResult.Issues, report.SoftwareAudit())
	createJsonFile(prismResult, filename)
}

/* ## Method to search Nipper XML and pull Audit information and format it into a finding for Prism ## */
func (r *Report) SoftwareAudit() PrismItem {
	issue := PrismItem{}
	issue.Name = "Software Audit"
	issue.Finding = "<p>Consultants performed a software vulnerability audit detailed in the technical details below.</p>"
	issue.Summary = "<p>The NVD published by NIST was used to compare the device type, model and software version against the database of known vulnerabilities. Each vulnerability finding is described with a CVE with details and information in the table shown below.</p>"
	issue.Recommendation = "<p>It is recommended that regardless of the number of vulnerabilities identified, they will all typically all be resolved by following the recommendations listed below;</p><ul><li>It is recommended that the latest software updates should be applied to all devices.</li><li>It is recommended that the current patching policy should be reviewed. That review should include the scheduling of updates and whether automation can be used to automatically deploy the updated versions. Although consultants understand that it may not be possible to achieve automation for all devices, this process should at least be attempted.</li><li>Finally, consultants recommend that all devices are regularly audited against the latest vulnerability databases to identify any systems that may be at risk.</li></ul>"
	issue.TechnicalDetails = "<p>A review of the current software was fopund to have the foolowing resulting CVE's:</p>"
	issue.OriginalRiskRating = "Info"
	issue.ClientDefinedRiskRating = "Info"
	audit_buff := []string{}
	open_table := "<table><tbody>"
	close_table := "</tbody></table>"
	audit_buff = append(audit_buff, open_table)
	report := r
	issue.AffectedHosts = Hosts(report)
	for _, section := range report.Sections.Section {
		for _, subsections := range section.Subsections.Section {
			if strings.Contains(subsections.Title, "CVE") {
				cve_name := subsections.Title
				cve_hosts := CVEgetHosts(subsections.Devices.Device)
				for _, cve := range subsections.Subsections.Section {
					discrip := []string{}
					for _, cont := range cve.Contents.Content {
						discrip = append(discrip, cont.CharData)
					}
					c := strings.Join(discrip, "")
					c = strings.TrimSpace(c)
					if len(c) > 166 {
						a := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%v</td></tr>", cve_name, strings.Replace(c, "Nipper performed a lookup of the CWE details as part of the vulnerability audit. This section details that information for this finding.", "", -1), cve_hosts)
						audit_buff = append(audit_buff, a)
						issue.Cves = append(issue.Cves, cve_name)
					}
				}
			}
		}
	}
	audit_buff = append(audit_buff, close_table)
	str := strings.Join(audit_buff, "\n")
	cwe, _ := regexp.Compile("CWE-[0-9]{2,4}")
	for _, c := range cwe.FindAllString(str, -1) {
		uri := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.Replace(c, "CWE-", "", -1))
		issue.References = append(issue.References, uri)
	}
	issue.References = RemoveDuplicatesFromSlice(issue.References)
	issue.TechnicalDetails = issue.TechnicalDetails + str
	return issue
}

/* ## Method to remove all Nipper phrasing and replace it with RS SOP compatable reporting ## */
func (p *PrismItem) NipperToPrism() PrismItem {
	issue := p
	issue.Finding = strings.Replace(issue.Finding, "Nipper", "Consultants", -1)
	issue.Recommendation = strings.Replace(issue.Recommendation, "Nipper recommends that ", "It is recommended that ", -1)
	issue.Recommendation = strings.Replace(issue.Recommendation, "Nipper suggests that ", "It is recommended that ", -1)
	issue.Recommendation = strings.Replace(issue.Recommendation, "Nipper strongly recommends that ", "It is recommended that ", -1)
	return *issue
}

/* ## Remove all duplicates from scrapped list ## */
func RemoveDuplicatesFromSlice(s []string) []string {
	m := make(map[string]bool)
	for _, item := range s {
		if _, ok := m[item]; ok {
		} else {
			m[item] = true
		}
	}
	var result []string
	for item, _ := range m {
		result = append(result, item)
	}
	return result
}

/* ## Get Devices from the head of the report ## */
func Hosts(r *Report) []PrismHost {
	var hosts []PrismHost
	for _, device := range r.Devices.Device {
		var host PrismHost
		host.Name = device.Name
		hosts = append(hosts, host)
	}
	return hosts
}

/* ## For each specific CVE get hosts ## */
func CVEgetHosts(devices []Device) string {
	var hosts []string
	var hhosts string
	for _, device := range devices {
		var host string
		host = device.Name
		hosts = append(hosts, host)
		hhosts = strings.Join(hosts, ", ")
	}
	return hhosts
}

func parseNipperFile(filename string) Report {
	xmlFile, err := os.Open(filename)

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("File found")
	defer xmlFile.Close()

	byteValue, _ := io.ReadAll(xmlFile)


	fmt.Println("Cleaning File")

	// Nipper files are invalid by default
	byteValue = cleanFile(byteValue)

	var result Report
	xml.Unmarshal([]byte(byteValue), &result)

	return result
}

func cleanFile(fileContents []byte) []byte {
	re := regexp.MustCompile(`3D="."`)

	return re.ReplaceAll([]byte(fileContents), []byte(""))
}

func createJsonFile(prismResult PrismBaseFile, filename string) {
	data, _ := json.Marshal(prismResult)

	var finalFilename = strings.Split(filename, ".")[0]

	fmt.Println("Creating File: " + finalFilename + "_prism.json")
	f, _ := os.Create(finalFilename + "_prism.json")
	f.WriteString(string(data))
	f.Sync()
}

func getHosts(devices []Device) []PrismHost {
	var hosts []PrismHost

	for _, device := range devices {
		var host PrismHost

		host.Name = device.Name

		hosts = append(hosts, host)
	}

	return hosts
}

func getContents(contents []Content) string {
	final := ""

	for _, content := range contents {
		final += "<p>" + content.CharData + "</p>"
	}

	return final
}
