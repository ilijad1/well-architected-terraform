package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "wat",
	Short: "AWS Well-Architected Terraform Analyzer",
	Long:  "Analyze Terraform configurations against the AWS Well-Architected Framework best practices.",
}

func Execute() error {
	return rootCmd.Execute()
}
