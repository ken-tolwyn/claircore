package oracle

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestVulnerableKsplice(t *testing.T) {
	matcher := &Matcher{}

	testcases := []struct {
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		name   string
		want   bool
	}{
		{
			name: "pkgVer contains ksplice",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.0.0-ksplice",
					Arch:    "x86_64",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Version: "1.0.0",
					Arch:    "x86_64",
				},
			},
			want: false,
		},
		{
			name: "vulnVer contains ksplice",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Version: "1.0.0",
					Arch:    "x86_64",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Version: "1.0.0-ksplice",
					Arch:    "x86_64",
				},
			},
			want: false,
		},
		{
			name: "both contain ksplice",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "kernel",
					Version: "1.0.0-ksplice",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Name:    "kernel",
					Version: "1.0.0-ksplice",
				},
			},
			want: true,
		},
		{
			name: "neither contain ksplice",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "kernel",
					Version: "1.0.0",
				},
			},
			vuln: &claircore.Vulnerability{
				Package: &claircore.Package{
					Name:    "kernel",
					Version: "1.0.0",
				},
			},
			want: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			got, err := matcher.Vulnerable(context.Background(), testcase.record, testcase.vuln)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.want) {
				t.Error(cmp.Diff(got, testcase.want))
			}
		})
	}
}

func TestMatcher(t *testing.T) {
	test.RunMatcherTests(zlog.Test(context.Background(), t), t, "testdata/matcher", new(Matcher))
}
