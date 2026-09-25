package report

import (
	"embed"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/metrics"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// chartWidth/chartHeight are the SVG user-space dimensions. The element itself
// scales to its container; these only set the coordinate system.
const (
	chartWidth  = 900
	chartHeight = 190
	chartPadTop = 8
)

// GridLine is one horizontal rule with its axis label.
type GridLine struct {
	X1, X2, Y, LabelY float64
	Label             string
}

// Chart holds precomputed SVG geometry. Building the points in Go keeps the
// report a single self-contained file with no JavaScript and no CDN.
type Chart struct {
	Width, Height float64
	TPSLine       string
	ErrorArea     string
	GridY         []GridLine
	MaxTPS        float64
	MaxErrRate    float64
	MaxSecond     int64
	HasData       bool
}

// BuildChart turns the per-second series into SVG geometry.
func BuildChart(rows []metrics.Second) Chart {
	c := Chart{Width: chartWidth, Height: chartHeight}
	if len(rows) == 0 {
		return c
	}

	for _, r := range rows {
		if v := float64(r.Completed); v > c.MaxTPS {
			c.MaxTPS = v
		}
		if r.Completed > 0 {
			if e := float64(r.Failure) / float64(r.Completed); e > c.MaxErrRate {
				c.MaxErrRate = e
			}
		}
		c.MaxSecond = r.Second
	}
	if c.MaxTPS <= 0 {
		return c
	}
	c.HasData = true

	// Round the axis up to a friendly value so the top gridline is meaningful.
	axisMax := niceCeil(c.MaxTPS)
	plotH := float64(chartHeight - chartPadTop - 12)
	xStep := chartWidth / math.Max(float64(len(rows)-1), 1)

	yFor := func(v float64) float64 {
		return chartPadTop + plotH*(1-v/axisMax)
	}

	var tps strings.Builder
	var area strings.Builder
	area.WriteString(fmt.Sprintf("0,%.1f ", chartPadTop+plotH))
	for i, r := range rows {
		x := float64(i) * xStep
		fmt.Fprintf(&tps, "%.1f,%.1f ", x, yFor(float64(r.Completed)))

		errRate := 0.0
		if r.Completed > 0 {
			errRate = float64(r.Failure) / float64(r.Completed)
		}
		fmt.Fprintf(&area, "%.1f,%.1f ", x, chartPadTop+plotH*(1-errRate))
	}
	fmt.Fprintf(&area, "%.1f,%.1f", float64(len(rows)-1)*xStep, chartPadTop+plotH)

	c.TPSLine = strings.TrimSpace(tps.String())
	if c.MaxErrRate > 0 {
		c.ErrorArea = strings.TrimSpace(area.String())
	}

	for _, f := range []float64{1, 0.5, 0} {
		y := yFor(axisMax * f)
		c.GridY = append(c.GridY, GridLine{
			X1: 0, X2: chartWidth, Y: y, LabelY: y - 2,
			Label: fmt.Sprintf("%.0f/s", axisMax*f),
		})
	}
	return c
}

// niceCeil rounds up to 1, 2 or 5 times a power of ten.
func niceCeil(v float64) float64 {
	if v <= 0 {
		return 1
	}
	mag := math.Pow(10, math.Floor(math.Log10(v)))
	switch n := v / mag; {
	case n <= 1:
		return mag
	case n <= 2:
		return 2 * mag
	case n <= 5:
		return 5 * mag
	default:
		return 10 * mag
	}
}

// reportData is the template context for a single-run report.
type reportData struct {
	Summary   *Summary
	Chart     Chart
	Generated time.Time
}

var funcs = template.FuncMap{
	"pct": func(f float64) string {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "—"
		}
		return fmt.Sprintf("%.2f%%", f*100)
	},
	"pct1": func(f float64) string { return fmt.Sprintf("%.1f", f) },
	"pct2": func(f float64) string { return fmt.Sprintf("%.2f", f) },
	"ms2":  func(f float64) string { return fmt.Sprintf("%.2f", f) },
	"secs": func(f float64) string { return (time.Duration(f * float64(time.Second))).Round(time.Second).String() },
	"utc":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 MST") },
	"barWidth": func(share float64) string {
		w := share * 100
		if w > 0 && w < 1 {
			w = 1
		}
		return fmt.Sprintf("%.1f", w)
	},
	// rateClass colours a success rate without hard-coding a pass/fail verdict:
	// what counts as acceptable is a commercial decision, not the tool's.
	"rateClass": func(rate float64) string {
		switch {
		case rate >= 0.999:
			return "good"
		case rate >= 0.99:
			return "mid"
		default:
			return "bad"
		}
	},
	"dict": func(pairs ...any) (map[string]any, error) {
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("dict requires an even number of arguments")
		}
		m := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			k, ok := pairs[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict keys must be strings")
			}
			m[k] = pairs[i+1]
		}
		return m, nil
	},
}

func parseTemplates(main string) (*template.Template, error) {
	return template.New(filepath.Base(main)).Funcs(funcs).
		ParseFS(templateFS, "templates/shared.html.tmpl", "templates/"+main)
}

// WriteHTML renders the single-run report.
func WriteHTML(path string, s *Summary, rows []metrics.Second, generated time.Time) (err error) {
	tmpl, err := parseTemplates("report.html.tmpl")
	if err != nil {
		return fmt.Errorf("parse report template: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	// A close error on a written file can mean the data never reached the
	// disk, so it must surface rather than be discarded by a bare defer.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	return tmpl.ExecuteTemplate(f, "report.html.tmpl", reportData{
		Summary:   s,
		Chart:     BuildChart(rows),
		Generated: generated,
	})
}
