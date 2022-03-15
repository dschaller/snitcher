package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	BaseUrl     = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
	UnifiedUrl  = "hosts"
	FakeNewsUrl = "alternates/fakenews/hosts"
	GamblingUrl = "alternates/gambling/hosts"
	PornUrl     = "alternates/porn/hosts"
	SocialUrl   = "alternates/social/hosts"
	MetaAddress = "0.0.0.0"
	HostRegex   = `0\.0\.0\.0\s(.+)$`
	TitleRegex  = `#\sTitle:\s(.+)$`
	OutputPath  = "RuleGroups/%s/%s.lsrules"
)

const ()

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type Rule struct {
	Action        `json:"action"`
	Process       string   `json:"process"`
	RemoteDomains []string `json:"remote-domains"`
}

type RuleGroup struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Rules       []*Rule `json:"rules"`
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func fetchHosts(path string) ([]string, error) {
	resp, err := http.Get(fmt.Sprintf("%s%s", BaseUrl, path))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(body), "\n"), nil
}

func unifiedDomains(domains map[string]bool) error {
	ptrn := regexp.MustCompile(HostRegex)
	hosts, err := fetchHosts(UnifiedUrl)
	if err != nil {
		return err
	}
	for _, v := range hosts {
		hstMtch := ptrn.FindStringSubmatch(v)
		if len(hstMtch) == 0 || hstMtch[1] == MetaAddress {
			continue
		}
		hstPts := strings.Fields(hstMtch[1])
		domain := hstPts[0]
		domains[domain] = true
	}
	return nil
}

func domainFor(url string) string {
	dmnPts := strings.Split(url, ".")
	if len(dmnPts) == 1 {
		return ""
	}
	return dmnPts[len(dmnPts)-2]
}

func generateRuleGroup(name, path string, action Action) error {
	ptrn := regexp.MustCompile(HostRegex)

	uniDmns := map[string]bool{}
	if path != UnifiedUrl {
		err := unifiedDomains(uniDmns)
		if err != nil {
			return err
		}
	}

	descPtrn := regexp.MustCompile(TitleRegex)
	rg := &RuleGroup{
		Name: name,
	}
	domains := map[string][]string{}
	hosts, err := fetchHosts(path)
	if err != nil {
		return err
	}
	for idx, v := range hosts {
		descMtch := descPtrn.FindStringSubmatch(v)
		if idx == 0 && len(descMtch) > 1 {
			rg.Description = descMtch[1]
			continue
		}
		hstMtch := ptrn.FindStringSubmatch(v)
		if len(hstMtch) == 0 || hstMtch[1] == MetaAddress {
			continue
		}
		hstPts := strings.Fields(hstMtch[1])
		domain := hstPts[0]

		if (path != UnifiedUrl && !uniDmns[domain]) || path == UnifiedUrl {
			d := domainFor(domain)
			if d == "" {
				continue
			}
			if domains[d] != nil && !contains(domains[d], domain) {
				domains[d] = append(domains[d], domain)
			} else {
				domains[d] = []string{domain}
			}
		}
	}
	rules := []*Rule{}
	for _, v := range domains {
		rules = append(rules, &Rule{
			Action:        action,
			Process:       "any",
			RemoteDomains: v,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return domainFor(rules[i].RemoteDomains[0]) < domainFor(rules[j].RemoteDomains[0])
	})
	rg.Rules = rules
	file, _ := json.MarshalIndent(rg, "", " ")
	err = ioutil.WriteFile(fmt.Sprintf(OutputPath, strings.Title(string(action)), name), file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	hosts := map[string]string{
		"StevenBlack-Unified":  UnifiedUrl,
		"StevenBlack-FakeNews": FakeNewsUrl,
		"StevenBlack-Gambling": GamblingUrl,
		"StevenBlack-Porn":     PornUrl,
		"StevenBlack-Social":   SocialUrl,
	}

	var wg sync.WaitGroup

	for _, a := range []Action{Allow, Deny} {
		wg.Add(1)
		go func(a Action) {
			defer wg.Done()
			for k, v := range hosts {
				err := generateRuleGroup(k, v, a)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					os.Exit(1)
				}
			}
		}(a)
	}

	wg.Wait()
}
