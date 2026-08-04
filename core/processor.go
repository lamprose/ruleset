package core

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	globalRegexCache sync.Map
)

func getCachedRegex(pattern string) *regexp.Regexp {
	if v, ok := globalRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	if c, err := regexp.Compile(pattern); err == nil {
		actual, _ := globalRegexCache.LoadOrStore(pattern, c)
		return actual.(*regexp.Regexp)
	}
	return nil
}

type ProcessedResult struct {
	DomRules           map[string][]string
	IPRules            map[string][]string
	WhiteDomRules      map[string][]string
	RawCount           int
	AddCount           int
	RmCount            int
	FinalCount         int
	WhiteCount         int
	ExactCounts        map[string]int
	UpstreamStats      map[string]int
	WhiteUpstreamStats map[string]int
	RawAdblockRules    map[string]bool
	RawDnsmasqRules    map[string]bool
	RawSmartDNSRules   map[string]bool
}

func ProcessCategory(cat Category, cfg *Config) *ProcessedResult {
	domains, suffixes, keywords, regexes := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	others := make(map[Rule]bool)

	rmExact := make(map[Rule]bool)
	rmDomains, rmSuffixes, rmKeywords, rmRegexes := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	whiteDomains, whiteSuffixes, whiteRegexes := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	ipv4Trie, ipv6Trie := &IPv4Trie{}, &IPv6Trie{}

	res := &ProcessedResult{
		DomRules:           make(map[string][]string),
		IPRules:            make(map[string][]string),
		WhiteDomRules:      make(map[string][]string),
		UpstreamStats:      make(map[string]int),
		WhiteUpstreamStats: make(map[string]int),
		RawAdblockRules:    make(map[string]bool),
		RawDnsmasqRules:    make(map[string]bool),
		RawSmartDNSRules:   make(map[string]bool),
		ExactCounts:        make(map[string]int),
	}

	processLine := func(line string, parserType string, isAdd bool, isRm bool, upURL string) {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" || strings.HasPrefix(cleanLine, "#") || strings.HasPrefix(cleanLine, "!") || strings.HasPrefix(cleanLine, "//") || strings.HasPrefix(cleanLine, "[") {
			return
		}

		if !isAdd && !isRm {
			if parserType == "adblock" {
				res.RawAdblockRules[cleanLine] = true
			} else if parserType == "dnsmasq" {
				res.RawDnsmasqRules[cleanLine] = true
			} else if parserType == "smartdns" {
				res.RawSmartDNSRules[cleanLine] = true
			}
		}

		if cat.AutoExtractWhite && !isAdd && !isRm {
			if w := ParseWhite(cleanLine); w != nil {
				if w.Type == "DOMAIN" { whiteDomains[w.Value] = true }
				if w.Type == "DOMAIN-SUFFIX" { whiteSuffixes[w.Value] = true }
				if w.Type == "DOMAIN-REGEX" { whiteRegexes[w.Value] = true }
				if upURL != "" { res.WhiteUpstreamStats[upURL]++ }
				behavior := cat.WhiteBehavior
				if behavior == "" { behavior = "remove" }
				if behavior == "remove" {
					res.RmCount++
					rmExact[*w] = true
					if w.Type == "DOMAIN" { rmDomains[w.Value] = true }
					if w.Type == "DOMAIN-SUFFIX" { rmSuffixes[w.Value] = true }
					if w.Type == "DOMAIN-REGEX" { rmRegexes[w.Value] = true }
				}
				return
			}
		}

		isExactRm := false
		if isRm && strings.HasPrefix(cleanLine, "EXACT:") {
			isExactRm = true
			cleanLine = strings.TrimSpace(strings.TrimPrefix(cleanLine, "EXACT:"))
		}

		r := Parse(cleanLine, parserType)
		if r == nil {
			return
		}

		if isRm {
			res.RmCount++

			rmExact[*r] = true
			
			if !isExactRm {
				if r.Type == "DOMAIN" {
					rmDomains[r.Value] = true
				}
				if r.Type == "DOMAIN-SUFFIX" {
					rmSuffixes[r.Value] = true
				}
				if r.Type == "DOMAIN-KEYWORD" {
					rmKeywords[r.Value] = true
				}
				if r.Type == "DOMAIN-REGEX" {
					rmRegexes[r.Value] = true
				}

				if r.Type == "IP-CIDR" || r.Type == "IP-CIDR6" {
					removeIP(r.Value, ipv4Trie, ipv6Trie)
				}
			}
			return
		}

		if isAdd {
			res.AddCount++
		} else {
			res.RawCount++
		}

		switch r.Type {
		case "DOMAIN":
			domains[r.Value] = true
		case "DOMAIN-SUFFIX":
			suffixes[r.Value] = true
		case "DOMAIN-KEYWORD":
			keywords[r.Value] = true
		case "DOMAIN-REGEX":
			regexes[r.Value] = true
		case "IP-CIDR", "IP-CIDR6":
			insertIP(r.Value, ipv4Trie, ipv6Trie)
		default:
			others[*r] = true
		}
	}

	loadEgernUpstream := func(f *os.File, upURL string) {
		scanner := bufio.NewScanner(f)
		linesBefore := res.RawCount
		currentEgernSection := ""

		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, ":") {
				currentEgernSection = strings.TrimSuffix(trimmed, ":")
				continue
			}
			
			cleanLine := strings.TrimSpace(line)
			if cleanLine == "" || strings.HasPrefix(cleanLine, "#") || strings.HasPrefix(cleanLine, "!") || strings.HasPrefix(cleanLine, "//") {
				continue
			}
			
			r := ParseEgern(line, currentEgernSection)
			if r != nil {
				res.RawCount++
				switch r.Type {
				case "DOMAIN":
					domains[r.Value] = true
				case "DOMAIN-SUFFIX":
					suffixes[r.Value] = true
				case "DOMAIN-KEYWORD":
					keywords[r.Value] = true
				case "DOMAIN-REGEX":
					regexes[r.Value] = true
				case "IP-CIDR", "IP-CIDR6":
					insertIP(r.Value, ipv4Trie, ipv6Trie)
				default:
					others[*r] = true
				}
			}
		}
		if upURL != "" {
			res.UpstreamStats[upURL] += res.RawCount - linesBefore
		}
	}

	loadUpstreams := func(targetCat Category) {
		for i, up := range targetCat.Upstreams {
			filePath := fmt.Sprintf("%s/%s_%d.txt", "temp/raw", targetCat.Name, i+1)
			if f, err := os.Open(filePath); err == nil {
				parserType := up.Parser
				if parserType == "" {
					parserType = InferParser(filePath)
				}

				if parserType == "egern" {
					loadEgernUpstream(f, up.URL)
				} else {
					scanner := bufio.NewScanner(f)
					linesBefore := res.RawCount
					for scanner.Scan() {
						processLine(scanner.Text(), parserType, false, false, up.URL)
					}
					res.UpstreamStats[up.URL] += res.RawCount - linesBefore
				}
				f.Close()
			}
		}
	}

	loadUpstreams(cat)
	for _, mergeCatName := range cat.MergeFrom {
		for _, c := range cfg.Categories {
			if c.Name == mergeCatName {
				loadUpstreams(c)
				break
			}
		}
	}

	if f, err := os.Open(fmt.Sprintf("add/%s.list", cat.Name)); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processLine(scanner.Text(), "clash", true, false, "Local Add")
		}
		f.Close()
	}

	if f, err := os.Open(fmt.Sprintf("remove/%s.list", cat.Name)); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processLine(scanner.Text(), "clash", false, true, "Local Remove")
		}
		f.Close()
	}

	for i, rmUp := range cat.RemoveURLs {
		filePath := fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cat.Name, i+1)
		if f, err := os.Open(filePath); err == nil {
			scanner := bufio.NewScanner(f)

			parserType := rmUp.Parser
			if parserType == "" {
				parserType = InferParser(filePath)
			}
			
			for scanner.Scan() {
				processLine(scanner.Text(), parserType, false, true, "Remote Remove")
			}
			f.Close()
		}
	}

	var compiledRegexes, compiledRmRegexes []*regexp.Regexp
	for reg := range regexes {
		if rmExact[Rule{"DOMAIN-REGEX", reg}] {
			continue
		}
		if c := getCachedRegex(reg); c != nil {
			compiledRegexes = append(compiledRegexes, c)
		}
	}
	for reg := range rmRegexes {
		if c := getCachedRegex(reg); c != nil {
			compiledRmRegexes = append(compiledRmRegexes, c)
		}
	}

	suffixTrie := NewSuffixTrie()
	for s := range rmSuffixes {
		suffixTrie.Insert(s)
	}
	for s := range suffixes {
		if !rmExact[Rule{"DOMAIN-SUFFIX", s}] {
			suffixTrie.Insert(s)
		}
	}

	isDomainKilled := func(d string) bool {
		if rmDomains[d] {
			return true
		}
		for kw := range rmKeywords {
			if strings.Contains(d, kw) {
				return true
			}
		}
		for _, re := range compiledRmRegexes {
			if re.MatchString(d) {
				return true
			}
		}
		if suffixTrie.MatchAnySuffix(d) {
			return true
		}
		for _, re := range compiledRegexes {
			if re.MatchString(d) {
				return true
			}
		}
		return false
	}

	isSuffixKilled := func(s string) bool {
		if rmSuffixes[s] {
			return true
		}
		for kw := range rmKeywords {
			if strings.Contains(s, kw) {
				return true
		    }
		}
		for _, re := range compiledRmRegexes {
			if re.MatchString(s) {
				return true
			}
		}
		if suffixTrie.MatchParentSuffix(s) {
			return true
		}
		for _, re := range compiledRegexes {
			if re.MatchString(s) && re.MatchString("test_dedupe."+s) {
				return true
			}
		}
		return false
	}

	isRegexKilled := func(r string) bool {
		if rmExact[Rule{"DOMAIN-REGEX", r}] {
			return true
		}
		orig := r
		if len(orig) > 1 && orig[0] == '^' {
			orig = orig[1:]
		}
		if len(orig) > 1 && orig[len(orig)-1] == '$' {
			orig = orig[:len(orig)-1]
		}

		if strings.HasPrefix(orig, `(.+\.)?`) {
			orig = "+." + orig[7:]
		} else if strings.HasPrefix(orig, `.+\.`) {
			orig = "." + orig[4:]
		}

		if orig == ".*" || orig == "[^.]+" {
			orig = "*"
		}
		orig = strings.ReplaceAll(orig, ".*", "*")
		orig = strings.ReplaceAll(orig, "[^.]+", "*")
		orig = strings.ReplaceAll(orig, `\.`, ".")
		orig = strings.ReplaceAll(orig, `\\`, `\`)

		if suffixTrie.MatchAnySuffix(orig) {
			return true
		}
		return false
	}

	for d := range domains {
		if rmExact[Rule{"DOMAIN", d}] {
			continue
		}
		if !isDomainKilled(d) {
			res.DomRules["DOMAIN"] = append(res.DomRules["DOMAIN"], d)
		}
	}
	for s := range suffixes {
		if rmExact[Rule{"DOMAIN-SUFFIX", s}] {
			continue
		}
		if !isSuffixKilled(s) {
			res.DomRules["DOMAIN-SUFFIX"] = append(res.DomRules["DOMAIN-SUFFIX"], s)
		}
	}
	for r := range regexes {
		if !isRegexKilled(r) {
			res.DomRules["DOMAIN-REGEX"] = append(res.DomRules["DOMAIN-REGEX"], r)
		}
	}
	for k := range keywords {
		if rmExact[Rule{"DOMAIN-KEYWORD", k}] {
			continue
		}
		res.DomRules["DOMAIN-KEYWORD"] = append(res.DomRules["DOMAIN-KEYWORD"], k)
	}

	for o := range others {
		if rmExact[o] {
			continue
		}
		t, v := o.Type, o.Value

		if t == "PROCESS-NAME" || t == "PROCESS-PATH" {
			res.DomRules[t] = append(res.DomRules[t], v)
		} else {
			res.IPRules[t] = append(res.IPRules[t], v)
		}
	}

	ipv4Trie.Walk(0, 0, &res.IPRules)
	ipv6Trie.Walk([16]byte{}, 0, &res.IPRules)

	whiteSuffixTrie := NewSuffixTrie()
	for s := range whiteSuffixes {
		whiteSuffixTrie.Insert(s)
	}

	isWhiteDomKilled := func(d string) bool {
		return whiteSuffixTrie.MatchAnySuffix(d)
	}

	isWhiteSufKilled := func(s string) bool {
		return whiteSuffixTrie.MatchParentSuffix(s)
	}

	for d := range whiteDomains {
		if !isWhiteDomKilled(d) {
			res.WhiteDomRules["DOMAIN"] = append(res.WhiteDomRules["DOMAIN"], d)
		}
	}
	for s := range whiteSuffixes {
		if !isWhiteSufKilled(s) {
			res.WhiteDomRules["DOMAIN-SUFFIX"] = append(res.WhiteDomRules["DOMAIN-SUFFIX"], s)
		}
	}
	for r := range whiteRegexes {
		res.WhiteDomRules["DOMAIN-REGEX"] = append(res.WhiteDomRules["DOMAIN-REGEX"], r)
	}

	for _, k := range []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH"} {
		if v, ok := res.DomRules[k]; ok {
			sort.Strings(v)
			res.FinalCount += len(v)
		}
	}

	for _, k := range []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-REGEX"} {
		if v, ok := res.WhiteDomRules[k]; ok {
			sort.Strings(v)
			res.WhiteCount += len(v)
		}
	}

	if v, ok := res.IPRules["IP-CIDR6"]; ok {
		var norm, ffff []string
		for _, ip := range v {
			if strings.HasPrefix(strings.ToLower(ip), "::ffff:") {
				ffff = append(ffff, ip)
			} else {
				norm = append(norm, ip)
			}
		}
		res.IPRules["IP-CIDR6"] = append(norm, ffff...)
	}

	for _, k := range []string{"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"} {
		if v, ok := res.IPRules[k]; ok {
			res.FinalCount += len(v)
		}
	}
	for _, k := range []string{"DST-PORT", "SRC-PORT", "NETWORK", "IP-ASN"} {
		if v, ok := res.IPRules[k]; ok {
			sort.Strings(v)
			res.FinalCount += len(v)
		}
	}

	fmt.Printf("Processed category: %s | Final count: %d\n", cat.Name, res.FinalCount)
	return res
}

type IPv4Trie struct {
	isLeaf bool
	child  [2]*IPv4Trie
}

func (t *IPv4Trie) Insert(ip uint32, length, depth int) {
	if t.isLeaf {
		return
	}
	if depth == length {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
		return
	}
	bit := (ip >> (31 - depth)) & 1
	if t.child[bit] == nil {
		t.child[bit] = &IPv4Trie{}
	}
	t.child[bit].Insert(ip, length, depth+1)
	if t.child[0] != nil && t.child[0].isLeaf && t.child[1] != nil && t.child[1].isLeaf {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
	}
}

func (t *IPv4Trie) Remove(ip uint32, length, depth int) {
	if t == nil {
		return
	}
	if depth == length {
		t.isLeaf = false
		t.child[0], t.child[1] = nil, nil
		return
	}
	if t.isLeaf {
		t.isLeaf = false
		t.child[0] = &IPv4Trie{isLeaf: true}
		t.child[1] = &IPv4Trie{isLeaf: true}
	}
	bit := (ip >> (31 - depth)) & 1
	if t.child[bit] != nil {
		t.child[bit].Remove(ip, length, depth+1)
	}
}

func (t *IPv4Trie) Walk(val uint32, depth int, out *map[string][]string) {
	if t == nil {
		return
	}
	if t.isLeaf {
		addr := netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
		(*out)["IP-CIDR"] = append((*out)["IP-CIDR"], netip.PrefixFrom(addr, depth).String())
		return
	}
	if t.child[0] != nil {
		t.child[0].Walk(val, depth+1, out)
	}
	if t.child[1] != nil {
		t.child[1].Walk(val|(1<<(31-depth)), depth+1, out)
	}
}

type IPv6Trie struct {
	isLeaf bool
	child  [2]*IPv6Trie
}

func (t *IPv6Trie) Insert(ip [16]byte, length, depth int) {
	if t.isLeaf {
		return
	}
	if depth == length {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
		return
	}
	bit := (ip[depth/8] >> (7 - (depth % 8))) & 1
	if t.child[bit] == nil {
		t.child[bit] = &IPv6Trie{}
	}
	t.child[bit].Insert(ip, length, depth+1)
	if t.child[0] != nil && t.child[0].isLeaf && t.child[1] != nil && t.child[1].isLeaf {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
	}
}

func (t *IPv6Trie) Remove(ip [16]byte, length, depth int) {
	if t == nil {
		return
	}
	if depth == length {
		t.isLeaf = false
		t.child[0], t.child[1] = nil, nil
		return
	}
	if t.isLeaf {
		t.isLeaf = false
		t.child[0] = &IPv6Trie{isLeaf: true}
		t.child[1] = &IPv6Trie{isLeaf: true}
	}
	bit := (ip[depth/8] >> (7 - (depth % 8))) & 1
	if t.child[bit] != nil {
		t.child[bit].Remove(ip, length, depth+1)
	}
}

func (t *IPv6Trie) Walk(val [16]byte, depth int, out *map[string][]string) {
	if t == nil {
		return
	}
	if t.isLeaf {
		(*out)["IP-CIDR6"] = append((*out)["IP-CIDR6"], netip.PrefixFrom(netip.AddrFrom16(val), depth).String())
		return
	}
	if t.child[0] != nil {
		t.child[0].Walk(val, depth+1, out)
	}
	if t.child[1] != nil {
		newVal := val
		newVal[depth/8] |= (1 << (7 - (depth % 8)))
		t.child[1].Walk(newVal, depth+1, out)
	}
}

func IP4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func insertIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	if p, err := netip.ParsePrefix(strings.Split(val, ",")[0]); err == nil {
		if p.Addr().Is4() {
			t4.Insert(IP4ToUint32(p.Addr()), p.Bits(), 0)
		} else {
			t6.Insert(p.Addr().As16(), p.Bits(), 0)
		}
	}
}

func removeIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	if p, err := netip.ParsePrefix(strings.Split(val, ",")[0]); err == nil {
		if p.Addr().Is4() {
			t4.Remove(IP4ToUint32(p.Addr()), p.Bits(), 0)
		} else {
			t6.Remove(p.Addr().As16(), p.Bits(), 0)
		}
	}
}

type SuffixTrie struct {
	isEnd    bool
	children map[string]*SuffixTrie
}

func NewSuffixTrie() *SuffixTrie {
	return &SuffixTrie{children: make(map[string]*SuffixTrie)}
}

func (t *SuffixTrie) Insert(suffix string) {
	if suffix == "" {
		return
	}
	curr := t
	for {
		idx := strings.LastIndexByte(suffix, '.')
		var part string
		if idx == -1 {
			part = suffix
		} else {
			part = suffix[idx+1:]
		}
		if curr.children[part] == nil {
			curr.children[part] = NewSuffixTrie()
		}
		curr = curr.children[part]
		if idx == -1 {
			break
		}
		suffix = suffix[:idx]
	}
	curr.isEnd = true
}

func (t *SuffixTrie) MatchAnySuffix(domain string) bool {
	if domain == "" {
		return false
	}
	curr := t
	for {
		idx := strings.LastIndexByte(domain, '.')
		var part string
		if idx == -1 {
			part = domain
		} else {
			part = domain[idx+1:]
		}
		if curr = curr.children[part]; curr == nil {
			return false
		}
		if curr.isEnd {
			return true
		}
		if idx == -1 {
			break
		}
		domain = domain[:idx]
	}
	return false
}

func (t *SuffixTrie) MatchParentSuffix(suffix string) bool {
	if suffix == "" {
		return false
	}
	curr := t
	for {
		idx := strings.LastIndexByte(suffix, '.')
		var part string
		if idx == -1 {
			part = suffix
		} else {
			part = suffix[idx+1:]
		}
		if curr = curr.children[part]; curr == nil {
			return false
		}
		if curr.isEnd && idx != -1 {
			return true
		}
		if idx == -1 {
			break
		}
		suffix = suffix[:idx]
	}
	return false
}