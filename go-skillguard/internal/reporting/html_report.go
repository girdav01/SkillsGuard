package reporting

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// GenerateHTMLReport generates an HTML report from scan results.
func GenerateHTMLReport(result *core.ScanResult) string {
	var b strings.Builder
	verdictStr := string(result.Verdict)
	verdictColor := verdictColorMap(result.Verdict)

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SkillGuard Scan Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
.container { max-width: 1000px; margin: 0 auto; }
.header { background: #1a1a2e; color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
.header h1 { margin: 0 0 10px 0; }
.summary { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }
.card { background: white; border-radius: 8px; padding: 20px; flex: 1; min-width: 200px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.card h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; text-transform: uppercase; }
.card .value { font-size: 28px; font-weight: bold; }
.verdict { display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; }
.findings { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.finding { border-left: 4px solid; padding: 12px; margin: 10px 0; background: #fafafa; border-radius: 0 4px 4px 0; }
.finding.critical { border-color: #dc3545; }
.finding.high { border-color: #fd7e14; }
.finding.medium { border-color: #ffc107; }
.finding.low { border-color: #28a745; }
.finding.info { border-color: #17a2b8; }
.snippet { background: #272822; color: #f8f8f2; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 13px; margin-top: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
th { background: #f0f0f0; }
</style>
</head>
<body>
<div class="container">
`)

	// Header
	b.WriteString(fmt.Sprintf(`<div class="header">
<h1>SkillGuard Scan Report</h1>
<p>Skill: <strong>%s</strong> | SHA256: <code>%s</code></p>
<p>Scanned: %s | Files: %d</p>
</div>
`, html.EscapeString(result.SkillName), result.SkillSHA256[:16]+"...",
		result.ScanCompleted.Format(time.RFC3339), result.FilesScanned))

	// Summary cards
	b.WriteString(`<div class="summary">`)
	b.WriteString(fmt.Sprintf(`<div class="card">
<h3>Risk Score</h3>
<div class="value">%d/100</div>
</div>`, result.CompositeScore))

	b.WriteString(fmt.Sprintf(`<div class="card">
<h3>Verdict</h3>
<div class="value"><span class="verdict" style="background:%s;color:white">%s</span></div>
</div>`, verdictColor, strings.ToUpper(verdictStr)))

	b.WriteString(fmt.Sprintf(`<div class="card">
<h3>Total Findings</h3>
<div class="value">%d</div>
</div>`, result.TotalFindings))

	b.WriteString(fmt.Sprintf(`<div class="card">
<h3>Engines</h3>
<div class="value">%d</div>
</div>`, len(result.EngineResults)))

	b.WriteString(`</div>`)

	// Engine results table
	b.WriteString(`<div class="findings" style="margin-bottom:20px">
<h2>Engine Results</h2>
<table>
<tr><th>Engine</th><th>Verdict</th><th>Findings</th><th>Duration</th></tr>`)

	for _, er := range result.EngineResults {
		b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td><td>%dms</td></tr>`,
			html.EscapeString(er.EngineName), string(er.Verdict), len(er.Findings), er.DurationMs))
	}
	b.WriteString(`</table></div>`)

	// Findings
	if result.TotalFindings > 0 {
		b.WriteString(`<div class="findings"><h2>Findings</h2>`)
		for _, er := range result.EngineResults {
			for _, f := range er.Findings {
				sevClass := strings.ToLower(string(f.Severity))
				b.WriteString(fmt.Sprintf(`<div class="finding %s">
<strong>[%s] %s</strong> — %s<br>
<small>File: %s`, sevClass,
					strings.ToUpper(string(f.Severity)),
					html.EscapeString(f.RuleName),
					html.EscapeString(f.Description),
					html.EscapeString(f.FilePath)))

				if f.LineStart != nil {
					b.WriteString(fmt.Sprintf(` | Line: %d`, *f.LineStart))
				}
				b.WriteString(`</small>`)

				if f.Snippet != nil && *f.Snippet != "" {
					b.WriteString(fmt.Sprintf(`<div class="snippet">%s</div>`, html.EscapeString(*f.Snippet)))
				}
				b.WriteString(`</div>`)
			}
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div></body></html>`)
	return b.String()
}

func verdictColorMap(verdict core.Verdict) string {
	switch verdict {
	case core.VerdictMalicious:
		return "#dc3545"
	case core.VerdictHighRisk:
		return "#fd7e14"
	case core.VerdictSuspicious:
		return "#ffc107"
	case core.VerdictLowRisk:
		return "#28a745"
	default:
		return "#17a2b8"
	}
}
