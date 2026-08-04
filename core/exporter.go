package core

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

type SingboxRuleSet struct {
	Version int              `json:"version"`
	Rules   []map[string]any `json:"rules"`
}

func toPortArray(vals []string) []any {
	var res []any
	for _, v := range vals {
		if n, err := strconv.Atoi(v); err == nil {
			res = append(res, n)
		} else {
			res = append(res, v)
		}
	}
	return res
}

func ensureDir(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("Failed to create directory [%s]: %v\n", path, err)
	}
}

func writeToFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("Failed to write file [%s]: %v\n", path, err)
	}
}

func ExportFiles(cat Category, res *ProcessedResult, cfg *Config) {
	ensureDir("process")
	ensureDir("publish/singbox")
	ensureDir("publish/mihomo")
	ensureDir("publish/v2ray")
	ensureDir("publish/surge")
	ensureDir("publish/shadowrocket")
	ensureDir("publish/quantumultx")
	ensureDir("publish/loon")
	ensureDir("publish/stash")
	ensureDir("publish/egern")

	catOut := ResolveClients(cfg.Global, cat)
	catName := cat.Name

	sbKeys := map[string]string{
		"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword", "DOMAIN-REGEX": "domain_regex",
		"PROCESS-NAME": "process_name", "PROCESS-PATH": "process_path",
		"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "SRC-IP-CIDR": "source_ip_cidr",
		"DST-PORT": "port", "SRC-PORT": "source_port", "NETWORK": "network", "IP-ASN": "ip_asn",
	}
	domKeys := []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH"}
	ipKeys := []string{"SRC-IP-CIDR", "DST-PORT", "SRC-PORT", "NETWORK", "IP-ASN"}

	countRules := func(dom map[string][]string, ip map[string][]string) int {
		c := 0
		for _, v := range dom { c += len(v) }
		for _, v := range ip { c += len(v) }
		return c
	}

	if cfg.Global.SplitCNIP && catName == "cn" {
		ensureDir("publish/cnip")
		var ipv4, ipv6 []string
		
		for _, ip := range res.IPRules["IP-CIDR"] { ipv4 = append(ipv4, strings.Split(ip, ",")[0]) }
		for _, ip := range res.IPRules["IP-CIDR6"] { ipv6 = append(ipv6, strings.Split(ip, ",")[0]) }

		if len(ipv4) > 0 { writeToFile("publish/cnip/cnipv4.txt", []byte(strings.Join(ipv4, "\n"))) }
		if len(ipv6) > 0 { writeToFile("publish/cnip/cnipv6.txt", []byte(strings.Join(ipv6, "\n"))) }
		
		res.ExactCounts["cnipv4"] = len(ipv4)
		res.ExactCounts["cnipv6"] = len(ipv6)
	}

	if catOut.Singbox.Enable {
		sbDomRules, sbIPRules := res.DomRules, res.IPRules
		
		res.ExactCounts["singbox_dom"] = countRules(sbDomRules, nil)
		res.ExactCounts["singbox_ip"] = countRules(nil, sbIPRules)
		res.ExactCounts["singbox_total"] = res.ExactCounts["singbox_dom"] + res.ExactCounts["singbox_ip"]
		
		hasDom := false
		srDom := SingboxRuleSet{Version: 5, Rules: []map[string]any{}}
		for _, t := range domKeys {
			if vals, ok := sbDomRules[t]; ok && len(vals) > 0 {
				srDom.Rules = append(srDom.Rules, map[string]any{sbKeys[t]: vals})
				hasDom = true
			}
		}

		hasIP := false
		srIP := SingboxRuleSet{Version: 5, Rules: []map[string]any{}}
		srIP_SRS := SingboxRuleSet{Version: 5, Rules: []map[string]any{}}

		var combinedIPs []string
		combinedIPs = append(combinedIPs, sbIPRules["IP-CIDR"]...)
		combinedIPs = append(combinedIPs, sbIPRules["IP-CIDR6"]...)
		if len(combinedIPs) > 0 {
			srIP.Rules = append(srIP.Rules, map[string]any{"ip_cidr": combinedIPs})
			srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{"ip_cidr": combinedIPs})
			hasIP = true
		}

		for _, t := range ipKeys {
			if vals, ok := sbIPRules[t]; ok && len(vals) > 0 {
				if t == "DST-PORT" || t == "SRC-PORT" || t == "IP-ASN" {
					srIP.Rules = append(srIP.Rules, map[string]any{sbKeys[t]: toPortArray(vals)})
					if t != "IP-ASN" {
						srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{sbKeys[t]: toPortArray(vals)})
					}
				} else {
					srIP.Rules = append(srIP.Rules, map[string]any{sbKeys[t]: vals})
					if t != "IP-ASN" {
						srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{sbKeys[t]: vals})
					}
				}
				hasIP = true
			}
		}

		writeSb := func(name string, rs SingboxRuleSet, isIP bool, rsSRS SingboxRuleSet) {
			if catOut.Singbox.JSON {
				if d, err := json.MarshalIndent(rs, "", "  "); err == nil {
					writeToFile(fmt.Sprintf("%s/%s.json", "publish/singbox", name), d)
				}
			}
			if catOut.Singbox.SRS {
				targetRS := rs
				if isIP { targetRS = rsSRS }
				if d, err := json.MarshalIndent(targetRS, "", "  "); err == nil {
					writeToFile(fmt.Sprintf("%s/srs_%s.json", "process", name), d)
				}
			}
		}

		if catOut.Singbox.SingleFile {
			srCombined := SingboxRuleSet{Version: 5, Rules: append(srDom.Rules, srIP.Rules...)}
			if len(srCombined.Rules) > 0 {
				writeSb(catName, srCombined, false, SingboxRuleSet{})
			}
		} else {
			if hasDom { writeSb(catName, srDom, false, SingboxRuleSet{}) }
			if hasIP  { writeSb(catName+"_ip", srIP, true, srIP_SRS) }
		}
	}

	if catOut.Mihomo.Enable {
		miDomRules, miIPRules := res.DomRules, res.IPRules
		
		res.ExactCounts["mihomo_dom"] = countRules(miDomRules, nil)
		res.ExactCounts["mihomo_ip"] = countRules(nil, miIPRules)
		res.ExactCounts["mihomo_total"] = res.ExactCounts["mihomo_dom"] + res.ExactCounts["mihomo_ip"]
		
		var yamlDomLines, yamlIPLines, listDomLines, listIPLines []string
		hasDom, hasIP := false, false

		for _, t := range domKeys {
			if vals, ok := miDomRules[t]; ok && len(vals) > 0 {
				for _, v := range vals {
					yamlDomLines = append(yamlDomLines, fmt.Sprintf("%s,%s", t, v))
				}
				hasDom = true
			}
		}
		if hasDom {
			for _, s := range miDomRules["DOMAIN-SUFFIX"] { listDomLines = append(listDomLines, "+."+s) }
			for _, d := range miDomRules["DOMAIN"] { listDomLines = append(listDomLines, d) }
			for _, r := range miDomRules["DOMAIN-REGEX"] {
				w := toMihomoWildcard(r)
				if w != "" && !strings.ContainsAny(w, "()[]|?^$") {
					listDomLines = append(listDomLines, w)
				}
			}
		}

		for _, k := range []string{"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT", "NETWORK", "IP-ASN"} {
			if vals, ok := miIPRules[k]; ok && len(vals) > 0 {
				for _, v := range vals {
					yamlIPLines = append(yamlIPLines, fmt.Sprintf("%s,%s", k, v))
					if k == "IP-CIDR" || k == "IP-CIDR6" || k == "SRC-IP-CIDR" {
						listIPLines = append(listIPLines, strings.Split(v, ",")[0])
					}
				}
				hasIP = true
			}
		}

		writeMihomoUserFiles := func(name string, classicalLines []string) {
			if catOut.Mihomo.YAML && len(classicalLines) > 0 {
				var yaml strings.Builder
				yaml.WriteString("payload:\n")
				for _, l := range classicalLines {
					yaml.WriteString(fmt.Sprintf("  - '%s'\n", l))
				}
				writeToFile(fmt.Sprintf("%s/%s.yaml", "publish/mihomo", name), []byte(yaml.String()))
			}
			
			if catOut.Mihomo.List && len(classicalLines) > 0 {
				writeToFile(fmt.Sprintf("%s/%s.list", "publish/mihomo", name), []byte(strings.Join(classicalLines, "\n")))
			}
		}

		if catOut.Mihomo.SingleFile {
			combinedLines := append(yamlDomLines, yamlIPLines...)
			writeMihomoUserFiles(catName, combinedLines)
		} else {
			if hasDom { writeMihomoUserFiles(catName, yamlDomLines) }
			if hasIP  { writeMihomoUserFiles(catName+"_ip", yamlIPLines) }
		}

		if catOut.Mihomo.MRS {
			if len(listDomLines) > 0 {
				writeToFile(fmt.Sprintf("%s/%s_mihomo_domain.list", "process", catName), []byte(strings.Join(listDomLines, "\n")))
			}
			if len(listIPLines) > 0 {
				writeToFile(fmt.Sprintf("%s/%s_mihomo_ip.list", "process", catName), []byte(strings.Join(listIPLines, "\n")))
			}
		}
	}

	if cat.PublishAdblock || cat.PublishDnsmasq || cat.PublishSmartDNS {
		adblockMap := make(map[string]bool)
		dnsmasqMap := make(map[string]bool)
		smartdnsMap := make(map[string]bool)

		dnsmasqTpl := "address=/%s/0.0.0.0"
		smartdnsTpl := "address /%s/#"

		if cat.DnsmasqServer != "" {
			dnsmasqTpl = fmt.Sprintf("server=/%%s/%s", cat.DnsmasqServer)
		}
		if cat.SmartdnsServer != "" {
			smartdnsTpl = fmt.Sprintf("nameserver /%%s/%s", cat.SmartdnsServer)
		}

		for _, s := range res.DomRules["DOMAIN-SUFFIX"] {
			if cat.PublishAdblock { adblockMap["||"+s+"^"] = true }
			if cat.PublishSmartDNS { smartdnsMap[fmt.Sprintf(smartdnsTpl, s)] = true }
			if cat.PublishDnsmasq { dnsmasqMap[fmt.Sprintf(dnsmasqTpl, s)] = true }
		}
		for _, d := range res.DomRules["DOMAIN"] {
			if cat.PublishAdblock { adblockMap["||"+d+"^"] = true }
			if cat.PublishSmartDNS { smartdnsMap[fmt.Sprintf(smartdnsTpl, d)] = true }
			if cat.PublishDnsmasq { dnsmasqMap[fmt.Sprintf(dnsmasqTpl, d)] = true }
		}
		for _, k := range res.DomRules["DOMAIN-KEYWORD"] {
			if cat.PublishAdblock { adblockMap[k] = true }
		}

		if cat.PublishAdblock {
			for l := range res.RawAdblockRules { adblockMap[l] = true }
		}
		if cat.PublishDnsmasq {
			for l := range res.RawDnsmasqRules { dnsmasqMap[l] = true }
		}
		if cat.PublishSmartDNS {
			for l := range res.RawSmartDNSRules { smartdnsMap[l] = true }
		}

		if cat.PublishAdblock && len(adblockMap) > 0 {
			ensureDir("publish/adblock")
			var lines []string
			for l := range adblockMap { lines = append(lines, l) }
			sort.Strings(lines)
			writeToFile(fmt.Sprintf("publish/adblock/%s.txt", catName), []byte(strings.Join(lines, "\n")))
		}
		if cat.PublishDnsmasq && len(dnsmasqMap) > 0 {
			ensureDir("publish/dnsmasq")
			var lines []string
			for l := range dnsmasqMap { lines = append(lines, l) }
			sort.Strings(lines)
			writeToFile(fmt.Sprintf("publish/dnsmasq/%s.conf", catName), []byte(strings.Join(lines, "\n")))
		}
		if cat.PublishSmartDNS && len(smartdnsMap) > 0 {
			ensureDir("publish/smartdns")
			var lines []string
			for l := range smartdnsMap { lines = append(lines, l) }
			sort.Strings(lines)
			writeToFile(fmt.Sprintf("publish/smartdns/%s.conf", catName), []byte(strings.Join(lines, "\n")))
		}
	}

	if catOut.V2ray.Enable {
		v2DomRules, v2IPRules := res.DomRules, res.IPRules
		var v2Lines []string

		for _, t := range domKeys {
			for _, v := range v2DomRules[t] {
				prefix := ""
				if t == "DOMAIN" { prefix = "full:" } else
				if t == "DOMAIN-SUFFIX" { prefix = "domain:" } else
				if t == "DOMAIN-REGEX" { prefix = "regexp:" } else
				if t == "DOMAIN-KEYWORD" { prefix = "" }
				v2Lines = append(v2Lines, prefix+v)
			}
		}

		var combinedIP []string
		for _, ip := range v2IPRules["IP-CIDR"] { combinedIP = append(combinedIP, strings.Split(ip, ",")[0]) }
		for _, ip := range v2IPRules["IP-CIDR6"] { combinedIP = append(combinedIP, strings.Split(ip, ",")[0]) }

		res.ExactCounts["v2ray_dom"] = len(v2Lines)
		res.ExactCounts["v2ray_ip"] = len(combinedIP)
		res.ExactCounts["v2ray_total"] = len(v2Lines) + len(combinedIP)

		if catOut.V2ray.SingleFile {
			var combined []string
			combined = append(combined, v2Lines...)
			combined = append(combined, combinedIP...)
			if len(combined) > 0 {
				writeToFile(fmt.Sprintf("publish/v2ray/%s.txt", catName), []byte(strings.Join(combined, "\n")))
			}
		} else {
			if len(v2Lines) > 0 { writeToFile(fmt.Sprintf("publish/v2ray/%s.txt", catName), []byte(strings.Join(v2Lines, "\n"))) }
			if len(combinedIP) > 0 { writeToFile(fmt.Sprintf("publish/v2ray/%s_ip.txt", catName), []byte(strings.Join(combinedIP, "\n"))) }
		}
	}

	buildAppleLines := func(isQX bool, ruleName string) ([]string, []string) {
		appleDomRules, appleIPRules := res.DomRules, res.IPRules
		var domLines, ipLines []string
		
		for _, t := range domKeys {
			for _, v := range appleDomRules[t] {
				writeType := t
				suffix := ""
				if isQX {
					writeType = strings.ReplaceAll(t, "DOMAIN", "HOST")
					suffix = "," + ruleName
				}
				domLines = append(domLines, fmt.Sprintf("%s,%s%s", writeType, v, suffix))
			}
		}
		for _, k := range []string{"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT", "NETWORK", "IP-ASN"} {
			for _, v := range appleIPRules[k] {
				suffix := ""
				if isQX {
					suffix = "," + ruleName
				} else {
					if k == "IP-CIDR" || k == "IP-CIDR6" || k == "SRC-IP-CIDR" {
						suffix = ",no-resolve"
					}
				}
				ipLines = append(ipLines, fmt.Sprintf("%s,%s%s", k, v, suffix))
			}
		}
		return domLines, ipLines
	}

	writeAppleFiles := func(clientName string, enable bool, singleFile bool, domLines, ipLines []string) {
		if !enable {
			return
		}
		
		res.ExactCounts[clientName+"_dom"] = len(domLines)
		res.ExactCounts[clientName+"_ip"] = len(ipLines)
		res.ExactCounts[clientName+"_total"] = len(domLines) + len(ipLines)

		if singleFile {
			var combined []string
			combined = append(combined, domLines...)
			combined = append(combined, ipLines...)
			if len(combined) > 0 {
				writeToFile(fmt.Sprintf("publish/%s/%s.list", clientName, catName), []byte(strings.Join(combined, "\n")))
			}
		} else {
			if len(domLines) > 0 {
				writeToFile(fmt.Sprintf("publish/%s/%s.list", clientName, catName), []byte(strings.Join(domLines, "\n")))
			}
			if len(ipLines) > 0 {
				writeToFile(fmt.Sprintf("publish/%s/%s_ip.list", clientName, catName), []byte(strings.Join(ipLines, "\n")))
			}
		}
	}

	type appleConf struct {
		name       string
		enable     bool
		singleFile bool
		isQX       bool
	}

	appleClients := []appleConf{
		{"surge", catOut.Surge.Enable, catOut.Surge.SingleFile, false},
		{"shadowrocket", catOut.Shadowrocket.Enable, catOut.Shadowrocket.SingleFile, false},
		{"loon", catOut.Loon.Enable, catOut.Loon.SingleFile, false},
		{"quantumultx", catOut.QuantumultX.Enable, catOut.QuantumultX.SingleFile, true},
		{"stash", catOut.Stash.Enable, catOut.Stash.SingleFile, false},
	}

	for _, client := range appleClients {
		if client.enable {
			d, i := buildAppleLines(client.isQX, catName)
			writeAppleFiles(client.name, true, client.singleFile, d, i)
		}
	}

	if catOut.Egern.Enable {
		egDomRules, egIPRules := res.DomRules, res.IPRules

		buildEgernYaml := func(doms, ips map[string][]string) string {
			var sb strings.Builder
			sb.WriteString("no_resolve: true\n")

			if vals := doms["DOMAIN"]; len(vals) > 0 {
				sb.WriteString("domain_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := doms["DOMAIN-KEYWORD"]; len(vals) > 0 {
				sb.WriteString("domain_keyword_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := doms["DOMAIN-SUFFIX"]; len(vals) > 0 {
				sb.WriteString("domain_suffix_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := doms["DOMAIN-REGEX"]; len(vals) > 0 {
				sb.WriteString("domain_regex_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := doms["PROCESS-NAME"]; len(vals) > 0 {
				sb.WriteString("user_agent_set:\n")
				for _, v := range vals {
					sb.WriteString(fmt.Sprintf("  - \"%s*\"\n", v)) 
				}
			}
			if vals := ips["IP-CIDR"]; len(vals) > 0 {
				sb.WriteString("ip_cidr_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := ips["IP-CIDR6"]; len(vals) > 0 {
				sb.WriteString("ip_cidr6_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := ips["IP-ASN"]; len(vals) > 0 {
				sb.WriteString("asn_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - \"%s\"\n", v)) }
			}
			return sb.String()
		}

		domCount := countRules(egDomRules, nil)
		ipCount := countRules(nil, egIPRules)

		res.ExactCounts["egern_dom"] = domCount
		res.ExactCounts["egern_ip"] = ipCount
		res.ExactCounts["egern_total"] = domCount + ipCount

		if catOut.Egern.SingleFile {
			if domCount+ipCount > 0 {
				content := buildEgernYaml(egDomRules, egIPRules)
				writeToFile(fmt.Sprintf("publish/egern/%s.yaml", catName), []byte(content))
			}
		} else {
			if domCount > 0 {
				content := buildEgernYaml(egDomRules, nil)
				writeToFile(fmt.Sprintf("publish/egern/%s.yaml", catName), []byte(content))
			}
			if ipCount > 0 {
				content := buildEgernYaml(nil, egIPRules)
				writeToFile(fmt.Sprintf("publish/egern/%s_ip.yaml", catName), []byte(content))
			}
		}
	}

	if cat.PublishWhite && len(res.WhiteDomRules) > 0 {
		whiteCat := cat

		whiteName := catName + "_white"
		if cat.WhiteName != "" {
			whiteName = cat.WhiteName
		}

		whiteCat.Name = whiteName
		whiteCat.PublishWhite = false
		
		disableV2ray := false
		whiteCat.V2ray = &CatV2rayOutput{Enable: &disableV2ray}

		whiteRes := &ProcessedResult{
			DomRules: res.WhiteDomRules,
			IPRules:  make(map[string][]string),
		}

		ExportFiles(whiteCat, whiteRes, cfg)
	}
}

func toMihomoWildcard(r string) string {
	clean := r
	clean = strings.TrimPrefix(clean, "^")
	clean = strings.TrimSuffix(clean, "$")
	if clean == "[^.]+" || clean == ".*" {
		return "*"
	}
	if strings.HasPrefix(clean, "(.+\\.)?") {
		clean = "+." + strings.TrimPrefix(clean, "(.+\\.)?")
	} else if strings.HasPrefix(clean, ".+\\.") {
		clean = "." + strings.TrimPrefix(clean, ".+\\.")
	}

	clean = strings.ReplaceAll(clean, ".*", "*")
	clean = strings.ReplaceAll(clean, "[^.]+", "*")
	clean = strings.ReplaceAll(clean, "\\.", ".")
	clean = strings.ReplaceAll(clean, "\\s", " ")
	return clean
}