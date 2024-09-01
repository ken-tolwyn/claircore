package oracle

import (
    "context"
    "testing"

    version "github.com/knqyf263/go-rpm-version"
    "github.com/quay/claircore"
    "github.com/stretchr/testify/assert"
)

func TestVulnerableKsplice(t *testing.T) {
    m := &Matcher{}
    ctx := context.Background()

    tests := []struct {
        name     string
        record   *claircore.IndexRecord
        vuln     *claircore.Vulnerability
        expected bool
    }{
        {
            name: "pkgVer contains ksplice",
            record: &claircore.IndexRecord{
                Package: claircore.Package{
                    Version: "1.0.0-ksplice",
                    Arch:    "x86_64",
                },
            },
            vuln: &claircore.Vulnerability{
                Package: claircore.Package{
                    Version: "1.0.0",
                    Arch:    "x86_64",
                },
            },
            expected: false,
        },
        {
            name: "vulnVer contains ksplice",
            record: &claircore.IndexRecord{
                Package: claircore.Package{
                    Version: "1.0.0",
                    Arch:    "x86_64",
                },
            },
            vuln: &claircore.Vulnerability{
                Package: claircore.Package{
                    Version: "1.0.0-ksplice",
                    Arch:    "x86_64",
                },
            },
            expected: false,
        },
        {
            name: "both contain ksplice",
            record: &claircore.IndexRecord{
                Package: claircore.Package{
                    Version: "1.0.0-ksplice",
                    Arch:    "x86_64",
                },
            },
            vuln: &claircore.Vulnerability{
                Package: claircore.Package{
                    Version: "1.0.0-ksplice",
                    Arch:    "x86_64",
                },
            },
            expected: true,
        },
        {
            name: "neither contain ksplice",
            record: &claircore.IndexRecord{
                Package: claircore.Package{
                    Version: "1.0.0",
                    Arch:    "x86_64",
                },
            },
            vuln: &claircore.Vulnerability{
                Package: claircore.Package{
                    Version: "1.0.0",
                    Arch:    "x86_64",
                },
            },
            expected: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := m.Vulnerable(ctx, tt.record, tt.vuln)
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}