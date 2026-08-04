package core

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

func CompileAll(cfg *Config) {
	fmt.Println("Compiling binary rule sets (SRS/MRS)...")

	needSRS, needMRS := false, false
	for _, cat := range cfg.Categories {
		out := ResolveClients(cfg.Global, cat)
		if out.Singbox.SRS { needSRS = true }
		if out.Mihomo.MRS { needMRS = true }
	}

	hasSingbox := checkCommand("sing-box") && needSRS
	hasMihomo := checkCommand("mihomo") && needMRS

	if !hasSingbox && needSRS {
		fmt.Println("sing-box not detected or SRS disabled, skipping .srs compilation.")
	}
	if !hasMihomo && needMRS {
		fmt.Println("mihomo not detected or MRS disabled, skipping .mrs compilation.")
	}

	if hasSingbox {
		files, _ := filepath.Glob("process" + "/srs_*.json")
		
		for _, file := range files {
			baseName := strings.TrimPrefix(filepath.Base(file), "srs_")
			outName := strings.TrimSuffix(baseName, ".json") + ".srs"
			outPath := filepath.Join("publish/singbox", outName)

			if err := exec.Command("sing-box", "rule-set", "compile", file, "-o", outPath).Run(); err != nil {
				fmt.Printf("Failed to compile (sing-box): %s\n", file)
			} else {
				fmt.Printf("Successfully compiled: %s\n", outPath)
			}
		}
	}

	if hasMihomo {
		domFiles, _ := filepath.Glob("process" + "/*_mihomo_domain.list")
		for _, file := range domFiles {
			catName := strings.TrimSuffix(filepath.Base(file), "_mihomo_domain.list")
			outFile := fmt.Sprintf("%s/%s.mrs", "publish/mihomo", catName)
			if err := exec.Command("mihomo", "convert-ruleset", "domain", "text", file, outFile).Run(); err == nil {
				fmt.Printf("Successfully compiled: %s\n", outFile)
			}
		}

		ipFiles, _ := filepath.Glob("process" + "/*_mihomo_ip.list")
		for _, file := range ipFiles {
			catName := strings.TrimSuffix(filepath.Base(file), "_mihomo_ip.list")
			outFile := fmt.Sprintf("%s/%s_ip.mrs", "publish/mihomo", catName)
			if err := exec.Command("mihomo", "convert-ruleset", "ipcidr", "text", file, outFile).Run(); err == nil {
				fmt.Printf("Successfully compiled: %s\n", outFile)
			}
		}
	}
}

func checkCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}