package core

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

	var wg sync.WaitGroup

	if hasSingbox {
		files, _ := filepath.Glob("process" + "/srs_*.json")
		
		for _, file := range files {
			wg.Add(1)
			
			go func(f string) {
				defer wg.Done()
				
				baseName := strings.TrimPrefix(filepath.Base(f), "srs_")
				outName := strings.TrimSuffix(baseName, ".json") + ".srs"
				outPath := filepath.Join("publish/singbox", outName)

				if err := exec.Command("sing-box", "rule-set", "compile", f, "-o", outPath).Run(); err != nil {
					fmt.Printf("Failed to compile (sing-box): %s\n", f)
				} else {
					fmt.Printf("Successfully compiled: %s\n", outPath)
				}
			}(file)
		}
	}

	if hasMihomo {
		domFiles, _ := filepath.Glob("process" + "/*_mihomo_domain.txt")
		for _, file := range domFiles {
			wg.Add(1)
			
			go func(f string) {
				defer wg.Done()
				
				catName := strings.TrimSuffix(filepath.Base(f), "_mihomo_domain.txt")
				outFile := fmt.Sprintf("%s/%s.mrs", "publish/mihomo", catName)
				if err := exec.Command("mihomo", "convert-ruleset", "domain", "text", f, outFile).Run(); err == nil {
					fmt.Printf("Successfully compiled: %s\n", outFile)
				} else {
					fmt.Printf("Failed to compile (mihomo domain): %s\n", f)
				}
			}(file)
		}

		ipFiles, _ := filepath.Glob("process" + "/*_mihomo_ip.txt")
		for _, file := range ipFiles {
			wg.Add(1)
			
			go func(f string) {
				defer wg.Done()
				
				catName := strings.TrimSuffix(filepath.Base(f), "_mihomo_ip.txt")
				outFile := fmt.Sprintf("%s/%s_ip.mrs", "publish/mihomo", catName)
				if err := exec.Command("mihomo", "convert-ruleset", "ipcidr", "text", f, outFile).Run(); err == nil {
					fmt.Printf("Successfully compiled: %s\n", outFile)
				} else {
					fmt.Printf("Failed to compile (mihomo ip): %s\n", f)
				}
			}(file)
		}
	}
	wg.Wait() 
}

func checkCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}