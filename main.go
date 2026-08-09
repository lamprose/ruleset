package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"diy-ruleset/core"
)

func main() {
	fmt.Println("Starting DIY-Ruleset...")

	_ = os.RemoveAll("publish")
	_ = os.RemoveAll("process")
	_ = os.RemoveAll("temp")

	defer os.RemoveAll("process")
	defer os.RemoveAll("temp")

	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		fmt.Println("config.yaml not detected; initializing default configuration using config-example.yaml...")
		exampleData, err := os.ReadFile("config-example.yaml")
		if err != nil {
			log.Fatalf("Configuration file not found, and config-example.yaml is also missing: %v", err)
		}
		if err := os.WriteFile("config.yaml", exampleData, 0644); err != nil {
			log.Fatalf("Unable to generate the default configuration file: %v", err)
		}
		fmt.Println("The default configuration file has been generated! Please edit config.yaml to customize your settings.")
	}

	cfg, err := core.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	core.FetchAll(cfg)

	fmt.Println("-----------------------------------")
	allResults := make(map[string]*core.ProcessedResult)
	
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, cat := range cfg.Categories {
		wg.Add(1)
		
		go func(c core.Category) {
			defer wg.Done()
			
			res := core.ProcessCategory(c, cfg)
			
			mu.Lock()
			allResults[c.Name] = res
			mu.Unlock()

			core.ExportFiles(c, res, cfg, false)
		}(cat)
	}

	wg.Wait() 

	fmt.Println("-----------------------------------")
	
	core.CompileAll(cfg)

	core.GenerateReport(allResults, cfg)

	_ = os.RemoveAll("process")
	_ = os.RemoveAll("temp")

	fmt.Println("Build completed successfully.")
}