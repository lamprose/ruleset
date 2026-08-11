package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

func FetchAll(cfg *Config) {
	os.RemoveAll("temp/raw")
	os.MkdirAll("temp/raw", 0755)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)
	client := &http.Client{Timeout: 30 * time.Second}

	var failedURLs []string
	var failMu sync.Mutex

	for _, cat := range cfg.Categories {
		for i, up := range cat.Upstreams {
			if up.URL == "" {
				continue
			}
			wg.Add(1)
			go func(cName string, idx int, u Upstream) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				
				if !downloadWithRetry(client, u.URL, fmt.Sprintf("%s/%s_%d.txt", "temp/raw", cName, idx+1), 3) {
					failMu.Lock()
					failedURLs = append(failedURLs, fmt.Sprintf("[%s] %s", cName, u.URL))
					failMu.Unlock()
				}
			}(cat.Name, i, up)
		}
		for i, rmUp := range cat.RemoveURLs {
			if rmUp.URL == "" {
				continue
			}
			wg.Add(1)
			go func(cName string, idx int, url string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				
				if !downloadWithRetry(client, url, fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cName, idx+1), 3) {
					failMu.Lock()
					failedURLs = append(failedURLs, fmt.Sprintf("[Remove-%s] %s", cName, url))
					failMu.Unlock()
				}
			}(cat.Name, i, rmUp.URL)
		}
	}
	wg.Wait()

	if len(failedURLs) > 0 {
		fmt.Println("\n================ WARNING ================")
		fmt.Printf("Failed to download %d upstream files:\n", len(failedURLs))
		for _, u := range failedURLs {
			fmt.Println(" -", u)
		}
		fmt.Println("=========================================")
	} else {
		fmt.Println("All upstream files downloaded successfully.")
	}
}

func downloadWithRetry(client *http.Client, url, dest string, retries int) bool {
	for i := 0; i < retries; i++ {
		success := func() bool {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			if token := os.Getenv("GITHUB_TOKEN"); token != "" {
				req.Header.Set("Authorization", "token "+token)
			}
			
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				out, err := os.Create(dest)
				if err != nil {
					return false
				}
				
				defer out.Close()
				
				_, err = io.Copy(out, resp.Body)

				if err == nil {
					return true
				}
				
				os.Remove(dest)
				fmt.Printf("Warning: Download incomplete for %s, corrupted file removed.\n", url)
			}
			return false
		}()
		if success {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}