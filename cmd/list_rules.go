package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
	_ "github.com/ilijad1/well-architected-terraform/internal/rules"
)

var listPillarFlag string

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all available analysis rules",
	RunE:  runListRules,
}

func init() {
	listRulesCmd.Flags().StringVar(&listPillarFlag, "pillar", "", "Filter by pillar (e.g., Security)")
	rootCmd.AddCommand(listRulesCmd)
}

func runListRules(cmd *cobra.Command, args []string) error {
	// Collect metadata from both single-resource and cross-resource rules.
	var allMeta []model.RuleMetadata
	for _, r := range engine.AllRules() {
		allMeta = append(allMeta, r.Metadata())
	}
	for _, r := range engine.AllCrossRules() {
		allMeta = append(allMeta, r.Metadata())
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tNAME\tSEVERITY\tPILLAR\tRESOURCES\n")
	fmt.Fprintf(w, "--\t----\t--------\t------\t---------\n")

	for _, meta := range allMeta {
		if listPillarFlag != "" && !strings.EqualFold(string(meta.Pillar), listPillarFlag) {
			continue
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			meta.ID,
			meta.Name,
			meta.Severity,
			shortenPillar(meta.Pillar),
			strings.Join(meta.ResourceTypes, ", "),
		)
	}

	return w.Flush()
}

func shortenPillar(p model.Pillar) string {
	switch p {
	case model.PillarSecurity:
		return "Security"
	case model.PillarReliability:
		return "Reliability"
	case model.PillarOperationalExcellence:
		return "Ops Excellence"
	case model.PillarPerformanceEfficiency:
		return "Performance"
	case model.PillarCostOptimization:
		return "Cost"
	case model.PillarSustainability:
		return "Sustainability"
	default:
		return string(p)
	}
}
