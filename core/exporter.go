package core

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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

func ExportFiles(cat Category, res *ProcessedResult, cfg *Config, isWhite bool) {
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
		"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "DST-PORT": "port",
	}
	domKeys := []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX", "URL-REGEX", "PROCESS-NAME", "PROCESS-PATH", "USER-AGENT"}
	ipKeys := []string{"DST-PORT", "IP-ASN"}

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

		writeCnipFiles := func(name string, ips []string) {
			if len(ips) == 0 { return }
			writeToFile(fmt.Sprintf("publish/cnip/%s.txt", name), []byte(strings.Join(ips, "\n")))
			if catOut.Singbox.SRS {
				rs := SingboxRuleSet{Version: 5, Rules: []map[string]any{{"ip_cidr": ips}}}
				if d, err := json.MarshalIndent(rs, "", "  "); err == nil {
					writeToFile(fmt.Sprintf("process/srs_cnip_%s.json", name), d)
				}
			}
			if catOut.Mihomo.MRS {
				writeToFile(fmt.Sprintf("process/cnip_%s_mihomo_ip.txt", name), []byte(strings.Join(ips, "\n")))
			}
		}

		writeCnipFiles("cnipv4", ipv4)
		writeCnipFiles("cnipv6", ipv6)
		
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
				var finalVals []string
				outType := t
				
				if t == "DOMAIN-WILDCARD" {
					outType = "DOMAIN-REGEX"
					for _, v := range vals { finalVals = append(finalVals, wildcardToRegex(v)) }
				} else if t == "URL-REGEX" || t == "USER-AGENT" {
					continue
				} else {
					finalVals = vals
				}
				
				sbKey := sbKeys[outType]
				if sbKey == "" { continue }
				
				srDom.Rules = append(srDom.Rules, map[string]any{sbKey: finalVals})
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
				sbKey := sbKeys[t]
				if sbKey == "" {
					continue
				}
				if t == "DST-PORT" {
					srIP.Rules = append(srIP.Rules, map[string]any{sbKey: toPortArray(vals)})
					srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{sbKey: toPortArray(vals)})
				} else {
					srIP.Rules = append(srIP.Rules, map[string]any{sbKey: vals})
					srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{sbKey: vals})
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
		
		var yamlDomLines, yamlIPLines, txtDomLines, txtIPLines []string
		hasDom, hasIP := false, false

		for _, t := range domKeys {
			if vals, ok := miDomRules[t]; ok && len(vals) > 0 {
				if t == "URL-REGEX" || t == "USER-AGENT" { continue }
				for _, v := range vals {
					yamlDomLines = append(yamlDomLines, fmt.Sprintf("%s,%s", t, v))
				}
				hasDom = true
			}
		}
		if hasDom {
			for _, s := range miDomRules["DOMAIN-SUFFIX"] { txtDomLines = append(txtDomLines, "+."+s) }
			for _, d := range miDomRules["DOMAIN"] { txtDomLines = append(txtDomLines, d) }
			for _, w := range miDomRules["DOMAIN-WILDCARD"] { txtDomLines = append(txtDomLines, w) }
			for _, r := range miDomRules["DOMAIN-REGEX"] {
				w := toMihomoWildcard(r)
				if w != "" && !strings.ContainsAny(w, "()[]|?^$") {
					txtDomLines = append(txtDomLines, w)
				}
			}
		}

		for _, k := range []string{"IP-CIDR", "IP-CIDR6", "DST-PORT", "IP-ASN"} {
			if vals, ok := miIPRules[k]; ok && len(vals) > 0 {
				for _, v := range vals {
					yamlIPLines = append(yamlIPLines, fmt.Sprintf("%s,%s", k, v))
					if k == "IP-CIDR" || k == "IP-CIDR6" {
						txtIPLines = append(txtIPLines, strings.Split(v, ",")[0])
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
			
			if catOut.Mihomo.TXT && len(classicalLines) > 0 {
				writeToFile(fmt.Sprintf("%s/%s.txt", "publish/mihomo", name), []byte(strings.Join(classicalLines, "\n")))
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
			if len(txtDomLines) > 0 {
				writeToFile(fmt.Sprintf("%s/%s_mihomo_domain.txt", "process", catName), []byte(strings.Join(txtDomLines, "\n")))
			}
			if len(txtIPLines) > 0 {
				writeToFile(fmt.Sprintf("%s/%s_mihomo_ip.txt", "process", catName), []byte(strings.Join(txtIPLines, "\n")))
			}
		}
	}

	if cat.PublishAdblock || cat.PublishDnsmasq || cat.PublishSmartDNS {
		var adblockLines, dnsmasqLines, smartdnsLines []string
		adblockDedupe := make(map[string]bool)
		dnsmasqDedupe := make(map[string]bool)
		smartdnsDedupe := make(map[string]bool)

		addRule := func(lines *[]string, dedupe map[string]bool, rule string) {
			if !dedupe[rule] {
				dedupe[rule] = true
				*lines = append(*lines, rule)
			}
		}

		for _, s := range res.DomRules["DOMAIN-SUFFIX"] {
			if cat.PublishAdblock {
				if isWhite { addRule(&adblockLines, adblockDedupe, "@@||"+s+"^") 
				} else { addRule(&adblockLines, adblockDedupe, "||"+s+"^") }
			}
		}
		for _, d := range res.DomRules["DOMAIN"] {
			if cat.PublishAdblock {
				if isWhite { addRule(&adblockLines, adblockDedupe, "@@|"+d+"|") 
				} else { addRule(&adblockLines, adblockDedupe, "||"+d+"^") }
			}
		}

		if cat.PublishAdblock && !isWhite {
			for _, s := range res.WhiteDomRules["DOMAIN-SUFFIX"] {
				addRule(&adblockLines, adblockDedupe, "@@||"+s+"^")
			}
			for _, d := range res.WhiteDomRules["DOMAIN"] {
				addRule(&adblockLines, adblockDedupe, "@@|"+d+"|")
			}
			for _, l := range res.RawWhiteAdblockRules {
				addRule(&adblockLines, adblockDedupe, l)
			}
		}

		if !isWhite {
			dnsmasqTpl := "address=/%s/0.0.0.0"
			smartdnsTpl := "address /%s/#"
			if cat.DnsmasqServer != "" { dnsmasqTpl = fmt.Sprintf("server=/%%s/%s", cat.DnsmasqServer) }
			if cat.SmartdnsServer != "" { smartdnsTpl = fmt.Sprintf("nameserver /%%s/%s", cat.SmartdnsServer) }

			for _, s := range res.DomRules["DOMAIN-SUFFIX"] {
				if cat.PublishSmartDNS { addRule(&smartdnsLines, smartdnsDedupe, fmt.Sprintf(smartdnsTpl, s)) }
				if cat.PublishDnsmasq { addRule(&dnsmasqLines, dnsmasqDedupe, fmt.Sprintf(dnsmasqTpl, s)) }
			}
			for _, d := range res.DomRules["DOMAIN"] {
				if cat.PublishSmartDNS { addRule(&smartdnsLines, smartdnsDedupe, fmt.Sprintf(smartdnsTpl, d)) }
				if cat.PublishDnsmasq { addRule(&dnsmasqLines, dnsmasqDedupe, fmt.Sprintf(dnsmasqTpl, d)) }
			}
		}

		if cat.PublishAdblock {
			for _, l := range res.RawAdblockRules { addRule(&adblockLines, adblockDedupe, l) }
		}
		
		if !isWhite {
			if cat.PublishDnsmasq {
				for _, l := range res.RawDnsmasqRules { addRule(&dnsmasqLines, dnsmasqDedupe, l) }
			}
			if cat.PublishSmartDNS {
				for _, l := range res.RawSmartDNSRules { addRule(&smartdnsLines, smartdnsDedupe, l) }
			}
		}

		if cat.PublishAdblock && len(adblockLines) > 0 {
			ensureDir("publish/adblock")
			writeToFile(fmt.Sprintf("publish/adblock/%s.txt", catName), []byte(strings.Join(adblockLines, "\n")))
		}
		if cat.PublishDnsmasq && len(dnsmasqLines) > 0 {
			ensureDir("publish/dnsmasq")
			writeToFile(fmt.Sprintf("publish/dnsmasq/%s.conf", catName), []byte(strings.Join(dnsmasqLines, "\n")))
		}
		if cat.PublishSmartDNS && len(smartdnsLines) > 0 {
			ensureDir("publish/smartdns")
			writeToFile(fmt.Sprintf("publish/smartdns/%s.conf", catName), []byte(strings.Join(smartdnsLines, "\n")))
		}
	}

	if catOut.V2ray.Enable {
		v2DomRules, v2IPRules := res.DomRules, res.IPRules
		var v2Lines []string

		for _, t := range domKeys {
			for _, v := range v2DomRules[t] {
				if t == "URL-REGEX" || t == "USER-AGENT" || t == "PROCESS-NAME" || t == "PROCESS-PATH" { continue }

				prefix := ""
				if t == "DOMAIN" { prefix = "full:" } else
				if t == "DOMAIN-SUFFIX" { prefix = "domain:" } else
				if t == "DOMAIN-REGEX" { prefix = "regexp:" } else
				if t == "DOMAIN-WILDCARD" { prefix = "regexp:"; v = wildcardToRegex(v) } else
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

	buildAppleLines := func(clientName string, ruleName string) ([]string, []string) {
		appleDomRules, appleIPRules := res.DomRules, res.IPRules
		var domLines, ipLines []string
		
		for _, t := range domKeys {
			for _, v := range appleDomRules[t] {
				writeType := t
				writeVal := v
				
				switch clientName {
				case "loon":
					if t == "DOMAIN-REGEX" || t == "DOMAIN-WILDCARD" { continue }
					if t == "PROCESS-NAME" || t == "PROCESS-PATH" { continue }
				case "surge":
					if t == "DOMAIN-REGEX" { continue }
					if t == "PROCESS-PATH" { continue }
				case "quantumultx":
					if t == "DOMAIN-REGEX" || t == "URL-REGEX" || t == "PROCESS-NAME" || t == "PROCESS-PATH" { continue }
					writeType = strings.ReplaceAll(t, "DOMAIN", "host")
					writeType = strings.ToLower(writeType)
				case "shadowrocket":
					if t == "DOMAIN-REGEX" { continue }
					if t == "PROCESS-NAME" || t == "PROCESS-PATH" { continue }
				case "stash":
				}

				suffix := ""
				if clientName == "quantumultx" {
					suffix = "," + ruleName
				}
				domLines = append(domLines, fmt.Sprintf("%s,%s%s", writeType, writeVal, suffix))
			}
		}
		
		appleIpKeys := []string{"IP-CIDR", "IP-CIDR6", "DST-PORT", "IP-ASN"}
		for _, k := range appleIpKeys {
			for _, v := range appleIPRules[k] {
				writeType := k
				
				switch clientName {
				case "surge", "loon":
					if writeType == "DST-PORT" { writeType = "DEST-PORT" }
				case "quantumultx":
					if writeType == "DST-PORT" { writeType = "dest-port" }
					if writeType == "IP-CIDR" { writeType = "ip-cidr" }
					if writeType == "IP-CIDR6" { writeType = "ip6-cidr" }
					if writeType == "IP-ASN" { writeType = "ip-asn" }
				}

				suffix := ""
				if clientName == "quantumultx" {
					suffix = "," + ruleName
				} else {
					if k == "IP-CIDR" || k == "IP-CIDR6" {
						suffix = ",no-resolve"
					}
				}
				ipLines = append(ipLines, fmt.Sprintf("%s,%s%s", writeType, v, suffix))
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
			d, i := buildAppleLines(client.name, catName)
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
			if vals := doms["DOMAIN-WILDCARD"]; len(vals) > 0 {
				sb.WriteString("domain_wildcard_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - %s\n", v)) }
			}
			if vals := doms["DOMAIN-REGEX"]; len(vals) > 0 {
				sb.WriteString("domain_regex_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - \"%s\"\n", v)) }
			}
			if vals := doms["URL-REGEX"]; len(vals) > 0 {
				sb.WriteString("url_regex_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - \"%s\"\n", v)) }
			}
			if vals := doms["USER-AGENT"]; len(vals) > 0 {
				sb.WriteString("user_agent_set:\n")
				for _, v := range vals { sb.WriteString(fmt.Sprintf("  - \"%s\"\n", v)) }
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
				for _, v := range vals {
					val := v
					if !strings.HasPrefix(strings.ToUpper(val), "AS") {
						val = "AS" + val
					}
					sb.WriteString(fmt.Sprintf("  - \"%s\"\n", val))
				}
			}
			if vals := ips["DST-PORT"]; len(vals) > 0 {
				sb.WriteString("dest_port_set:\n")
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
		whiteCat.Name = catName + "_white"
		whiteCat.PublishWhite = false
		whiteCat.PublishAdblock = false
		whiteCat.PublishDnsmasq = false
		whiteCat.PublishSmartDNS = false
		whiteRes := &ProcessedResult{
			DomRules: res.WhiteDomRules,
			IPRules:  make(map[string][]string),
			ExactCounts: make(map[string]int),
		}
		ExportFiles(whiteCat, whiteRes, cfg, true)
		for k, v := range whiteRes.ExactCounts {
			res.ExactCounts[k+"_white"] = v
		}
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

func wildcardToRegex(w string) string {
	r := strings.ReplaceAll(w, ".", `\.`)
	r = strings.ReplaceAll(r, "*", `.*`)
	r = strings.ReplaceAll(r, "?", `.`)
	return "^" + r + "$"
}