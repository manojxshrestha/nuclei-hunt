# 🔍🐞 The Ultimate Guide to Finding Bugs With Nuclei 🚀⚡

<p align="center">
  <img src="https://github.com/user-attachments/assets/090f1135-4c04-41fd-a795-6079df8ac39a" width="600">
</p>

Yo, what's up! Ready to become a pro bug hunter? Meet Nuclei—the ultra-fast, YAML-powered vulnerability scanner that’s basically a hacker’s best friend. Developed by the legends over at ProjectDiscovery, this tool is all about speed, flexibility, and cutting through the noise. Whether you're out there hunting bugs, pentesting, or just ethically breaking stuff, Nuclei has got you covered.

In this guide, we’re gonna take you from total newbie to certified pro. We'll walk you through installing it, picking the right templates, tweaking your scans, and, of course, snagging those juicy vulnerabilities. Let’s get it—time to dive in!!

---

## What’s Nuclei All About?

Picture this: a tool that’s fast as hell, uses simple YAML templates to hunt vulnerabilities, and lets you customize it like a pro. That’s Nuclei. It’s community-driven, with thousands of pros constantly contributing templates to keep it fresh and on-point. Nuclei isn’t just another scanner—it mimics real-world attack steps to eliminate the false positives and keep your findings legit.

And it doesn’t stop there. Nuclei scales like a champ. Whether you’re scanning a single URL, working through massive lists, or even running it in a CI/CD pipeline, Nuclei’s got you covered. It can hit everything from HTTP, TCP, DNS, and even JavaScript. Plus, it integrates smoothly with tools like Jira and Splunk, making it a powerful part of your workflow.

Bug hunting just got a turbo boost. No more messing around with slow, inefficient tools. Nuclei’s your go-to for fast, accurate, and customizable vulnerability scanning.

---

## Getting Started: Install and Learn how to use?


## 1. First, let’s get Nuclei installed on your machine. If you've got Go, you're good to go:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
Or grab a pre-built binary from GitHub—your call. Once it’s in, update the templates:
```bash
nuclei -update-templates
```
These YAMLs live in `nuclei-templates/` (more on that beast later) and are your vuln-hunting ammo.

---

## 2. Default Mode

Start simple—point Nuclei at a target and let it go:
```bash
nuclei -u http://target.com
```
This scans `target.com` with default templates—thousands of checks for CVEs, misconfigs, and more. Got open ports? Say, SSH on 22:
```bash
nuclei -u http://target.com:22
```
It’ll probe port 22 for SSH-specific vulns—like weak creds or old exploits. Expect goodies like DNS records or service banners in the output. Try it—it’s a quick way to see what’s exposed.

**Pro Tip**: Add `-v` for verbose mode—`nuclei -u http://target.com -v`—to peek at what’s triggered.

---

## 3. Scanning Multiple Sites

One target’s cool, but let’s scale up. Use `-l` with a list:
```bash
echo "target.com" > domains.txt
echo "app.target.com" >> domains.txt
nuclei -l domains.txt
```
Nuclei hits every site in `domains.txt`. Perfect for scoping a big target or a bounty program.

**Pro Tip**: Generate that list live: `subfinder -d target.com > domains.txt && nuclei -l domains.txt`.

---

## 4. Tool Integration

Why solo when you can combo? Chain Nuclei with other tools:
```bash
subfinder -d target.com | httpx | nuclei -t "http/technologies/prestashop-detect.yaml"
```
- `subfinder`: Grabs subdomains (e.g., `app.target.com`).
- `httpx`: Filters live hosts.
- `nuclei`: Checks for PrestaShop with a tech-specific template.

Swap that template for `cves/` or `vulnerabilities/` to widen the net. This is bug-hunting automation at its finest.

**Pro Tip**: Pipe to a file—`subfinder -d target.com | httpx | nuclei -t http/cves/ -o results.txt`.

---

## 5. Filtering

Nuclei’s got filters to cut the unnecessary results. Don’t know what to scan? Just go with auto:
```bash
nuclei -u http://target.com -as
```
`-as` uses Wappalyzer to detect tech and pick templates—smart and lazy. Want the latest greatest?
```bash
nuclei -u http://target.com -nt
```
`-nt` runs only new templates from the latest `nuclei-templates` drop.

Filter by tags:
```bash
nuclei -u https://jira.target.com -tags jira,generic
```
Hits Jira-specific and generic checks—great for known apps. Or by severity:
```bash
nuclei -u http://target.com -s critical,high,medium,low,info -as
```
From RCEs to info leaks—your call.

**Pro Tip**: Mix it up—`nuclei -u target.com -tags xss -s critical,high`.

---

## 6. Using Multiple Tags

Target different platforms in one go:
```bash
nuclei -u http://target.com -tags joomla,wordpress
```
This scans `target.com` for Joomla and WordPress vulns—handy if it’s a CMS stack. Add more tags:
```bash
nuclei -u http://target.com -tags joomla,wordpress,drupal,magento
```
Covers the big CMS players. Tags are your precision tool—use ‘em!

**Pro Tip**: View all tags with nuclei -tgl—there’s plenty to explore..

---

## 7. Scanning for a Specific CVE

Got a CVE in mind? Hunt it down:
```bash
nuclei -t cves/ -tags cve-2023-1234 -u http://target.com
```
This targets `cve-2023-1234` in the `cves/` dir—specific and impactful. The `nuclei-templates/http/cves/` collection goes from 2000 to 2025—select your risk.

**Pro Tip**: Validate findings—`nuclei -t cves/ -tags cve-2023-1234 -u target.com -validate`.

---

## 8. Scan by Technology

Know the target’s tech? Zero in:
```bash
nuclei -t http/technologies/ -tags wordpress -u http://target.com
```
Detects WordPress and runs WP-specific checks. Try others—`nginx`, `apache`, `laravel`—all in `http/technologies/`.

**Pro Tip**: Auto-detect first—`nuclei -u target.com -as`—then refine with tech tags.

---

## 9. Scan for Specific Vulnerabilities

Chase specific vulns like LFI:
```bash
nuclei -t dast/vulnerabilities/ -tags lfi -u http://target.com
```
Or XSS:
```bash
nuclei -t dast/vulnerabilities/ -tags xss -u http://target.com
```
SQLi? You got it:
```bash
nuclei -t dast/vulnerabilities/ -tags sqli -u http://target.com
```
These live in `dast/vulnerabilities/`—XSS, SQLi, SSRF, even SSTI/OOB (out-of-band fun).

**Pro Tip**: Add `-dast` for dynamic testing—`nuclei -t dast/vulnerabilities/ -tags sqli -u target.com -dast`.

---

## 10. Scan with Multiple Vulnerabilities

Why pick one? Hit multiple:
```bash
nuclei -t dast/vulnerabilities/ -tags xss,sqli,lfi -u http://target.com
```
Scans `target.com` for XSS, SQLi, and LFI in one shot. Stack ‘em up—`rce`, `ssrf`, `xxe`—whatever you’re into.

**Pro Tip**: Narrow by severity—`nuclei -t dast/vulnerabilities/ -tags xss,sqli -s critical -u target.com`.

---

## 11. Templates

Templates are the heart of Nuclei—786 dirs in `nuclei-templates/`. Explore with `ls nuclei-templates/`:
```
cloud  code  cves.json  dast  dns  file  headless  helpers  http  javascript  network  passive  profiles  ssl  workflows
```
- `cloud/aws/s3/`: Leaky buckets.
- `http/cves/2023/`: Fresh CVEs.
- `dast/vulnerabilities/ssti/oob/`: SSTI with OOB detection.

Browse [nuclei-templates.netlify.app](https://nuclei-templates.netlify.app/)—search “DNS” or “RCE”, grab a YAML, and run:
```bash
nuclei -u http://target.com -t dns-check.yaml
```
Write your own:
```yaml
id: target-debug
info:
  name: "Target Debug Check"
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
    matchers:
      - type: word
        words:
          - "Debug Mode"
```
`nuclei -u target.com -t target-debug.yaml`—custom bug hunting, baby.

---

## 12. Rate Limiting

Don’t DDoS your target—pace it:
```bash
nuclei -u http://target.com -rl 3 -c 2
```
- `-rl 3`: 3 requests/sec.
- `-c 2`: 2 concurrent templates.

Fine-tune:
```bash
nuclei -u http://target.com -timeout 10 -retries 3 -mhe 5
```
- `-timeout 10`: 10s wait.
- `-retries 3`: Retry 3 times.
- `-mhe 5`: Skip after 5 errors.

**Pro Tip**: Test limits safely—`nuclei -u target.com -rl 1`—no bans here.

---

## 13. Resume Scan

Big scan crash? Resume it:
```bash
nuclei -l domains.txt -resume ~/.config/nuclei/resume-*.cfg
```
Find your `.cfg` in `~/.config/nuclei/`—Nuclei’s got your back.

**Pro Tip**: Monitor live—`nuclei -l domains.txt -stats -si 5`—stats every 5s.

---

## 14. Output Options

Save your wins:
```bash
nuclei -t nuclei-templates/ -tags cve2010,cve,joomla,lfi,edb -u http://target.com -o results.txt
```
- `-o results.txt`: Plain text.
- `-j -o results.json`: JSONL.
- `-me report/`: Markdown—pretty reports.

Mix tags and vulns, then export—team loves that.

**Pro Tip**: Silent mode—`nuclei -u target.com -silent -o hits.txt`—just the goods.

---


# The Template Treasure Trove: Inside `nuclei-templates`

If Nuclei’s the engine, then `nuclei-templates` is the fuel—and trust me, it’s a full-on tanker! This is where the magic happens: a massive, community-powered collection of YAML files, all set to hunt vulnerabilities across every corner of the digital world. Let’s crack it open—peek inside with `tree -d` and `ls`, and see what treasures are waiting for you to unleash.

---

## The Big Picture: 786 Directories of Goodness

Run `tree -d nuclei-templates`, and you’ll see a beast—786 directories deep. It’s a bug hunter’s playground, covering everything from cloud misconfigs to ancient CVEs. Here’s the rundown straight from the terminal:

- **cloud/**: Misconfigs in the big three and more.
  - **alibaba/**: ACK, OSS, RAM—think leaky buckets or weak perms.
  - **aws/**: S3, EC2, IAM—exposed buckets, anyone? Subdirs like `s3/` and `secrets-manager/` are gold.
  - **azure/**: KeyVault, AKS, SQL—Azure’s got its own skeletons.
  - **kubernetes/**: Pods, deployments—K8s flaws like misconfigured RBAC.
- **code/**: Static code checks.
  - **cves/**: Years like `2014/` to `2024/`—CVEs in source code.
  - **privilege-escalation/**: Linux binaries, Windows audits—privesc heaven.
- **dast/**: Dynamic testing firepower.
  - **cves/**: `2018/` to `2024/`—dynamic CVE checks.
  - **vulnerabilities/**: XSS, SQLi, SSRF—subdirs like `ssti/oob/` for out-of-band goodies.
- **dns/**: DNS misconfigs and vulns—short but sweet.
- **file/**: File-based hunting.
  - **keys/**: creds galore—`github/`, `aws/`, `discord/`—leaked tokens everywhere.
  - **webshell/**, **malware/**: Spotting nasty stuff in files.
- **headless/**: Browser-based magic.
  - **cves/**: `2018/`, `2024/`—headless CVE checks.
  - **vulnerabilities/retool/**: Niche app flaws.
- **http/**: The web app jackpot.
  - **cves/**: `2000/` to `2025/`—two decades of pain.
  - **default-logins/**: `jenkins/`, `grafana/`, `wordpress/`—weak creds galore.
  - **exposures/**: `tokens/github/`, `configs/`—leaked secrets and backups.
  - **vulnerabilities/**: `wordpress/`, `springboot/`, `laravel/`—CMS and framework bugs.
- **javascript/**: JS-specific scans.
  - **cves/**: `2012/` to `2024/`.
  - **enumeration/**: `ldap/`, `redis/`—JS-based service probes.
- **network/**: Beyond HTTP.
  - **cves/**: `2001/` to `2023/`.
  - **misconfig/**: SSH, SMTP—network weak spots.
- **passive/**: Passive scanning—`cves/2024/` and counting.
- **ssl/**: TLS flaws—`fortinet/`, `c2/` subdirs.
- **workflows/**: Chained template goodness.

That’s the `tree -d` view—786 dirs of pure potential. It’s like a bug bounty candy store.

---

## How to work with it

These templates are your ammo. Pick a dir with `-t`:
- Cloud leaks: `nuclei -u target.com -t cloud/aws/s3/`.
- Web CVEs: `nuclei -u target.com -t http/cves/2023/`.
- Fuzzing: `nuclei -u target.com -t dast/vulnerabilities/xss/ -dast`.

The `tree` shows the depth—dig into `http/vulnerabilities/wordpress/` for WP bugs or `file/keys/github/` for token leaks. The `ls` ls shows you the top-level structure—start wide, then dive deeper.

---

## Why It’s a Treasure Trove

With 786 dirs, `nuclei-templates` covers the gamut—cloud, web, network, code, you name it. It’s community-driven, so you’re riding thousands of hours of bug-hunting wisdom. It’s community-driven, so you’re tapping into thousands of hours of bug-hunting expertise. Whether you’re after a quick AWS S3 win or a deep-dive WordPress RCE, it’s all here. Explore, experiment, and you’ll strike treasure.

Pick your poison with `-t`:
```bash
nuclei -u target.com -t http/cves/
```
That’s just the tip—custom templates are where you’ll shine.

---

## Command-Line Mastery: Nuclei Flags 101

Run `nuclei -h`, and you’ll see a wall of flags—don’t freak, it’s your toolbox. Here’s the rundown:

### Targeting
- `-u target.com`: Single URL.
- `-l hosts.txt`: List of targets—`echo "target.com" > hosts.txt && nuclei -l hosts.txt`.
- `-sa`: Scan all IPs for a domain—`nuclei -u target.com -sa`.

### Templates
- `-t http/cves/`: Specific dir—`nuclei -u target.com -t http/cves/`.
- `-w workflows/`: Chain templates—`nuclei -u target.com -w login-bypass.yaml`.
- `-nt`: Newest templates—`nuclei -u target.com -nt`.

### Filtering
- `-s critical`: High-impact only—`nuclei -u target.com -s critical`.
- `-tags xss`: Tag-based—more on tags in a sec.
- `-tc "status_code == 200"`: Conditional—custom logic FTW.

### Output
- `-o bugs.txt`: Save findings—`nuclei -u target.com -o bugs.txt`.
- `-j -o bugs.json`: JSONL—`nuclei -u target.com -j -o bugs.json`.
- `-me report/`: Markdown—`nuclei -u target.com -me report/`.

### Configs
- `-c 50`: Concurrency—`nuclei -u target.com -c 50`.
- `-rl 300`: Rate limit—`nuclei -u target.com -rl 300`.
- `-H "Cookie: abc"`: Custom headers—authenticated scans, baby.

### Fuzzing
- `-dast`: Dynamic testing—`nuclei -u target.com -dast`.
- `-fa high`: Aggression level—`nuclei -u target.com -dast -fa high`.

Check the full `nuclei -h` for more—like `-headless` for browser stuff or `-uc` for Shodan integration. It’s a playground.

---

## Tags: Your Targeted Scans

Nuclei’s templates come with tags—think of ‘em as labels for laser-focused scans. Here’s the lineup:

### CVE Tags
- `cve-2023-1234`: Specific CVEs—`nuclei -t cves/ -tags cve-2023-1234 -u target.com`.

### OWASP Top 10
- `owasp-a7`: XSS—`nuclei -t vulnerabilities/ -tags owasp-a7 -u target.com`.
- `owasp-a1`: Injection—SQLi, CMDi, etc.

### Web App Tags
- `xss`, `sqli`, `rce`, `ssrf`—`nuclei -t http/ -tags xss -u target.com`.

### API Tags
- `graphql`, `token-leak`—`nuclei -t exposures/ -tags token-leak -u target.com`.

### Cloud Tags
- `aws`, `kubernetes`—`nuclei -t cloud/ -tags aws -u target.com`.

### Network Tags
- `ssh`, `dns`—`nuclei -t network/ -tags ssh -u target.com`.

Combine ‘em: `nuclei -t http/ -tags "xss,sqli" -u target.com`. Precision, mate.

---

## Crafting Custom Templates: Your Secret Weapon

Default templates are dope, but custom ones win bounties. Here’s a simple YAML to detect an exposed debug page:
```yaml
id: debug-page-check
info:
  name: "Exposed Debug Page"
  author: "you"
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
    matchers:
      - type: word
        words:
          - "Debug Mode Enabled"
```
Run it: `nuclei -u target.com -t debug-page-check.yaml`. Found something? You’re the first—claim that bug!

---

## Workflows: Chaining the Magic

Workflows string templates together. Example:
```yaml
id: login-bypass
info:
  name: "Login Bypass Check"
workflows:
  - template: "http/login-detect.yaml"
    matchers:
      - name: "login-found"
  - template: "http/bypass.yaml"
```
`nuclei -u target.com -w login-bypass.yaml`—detects a login, then tests for bypass. Combo moves, baby.

---

## Pro Tips: Level Up Your Game

- **Race Conditions**: Add `race: true` and `race_count: 10` to a template—`nuclei -u target.com -t race.yaml`. Timing bugs beware.
- **Fuzzing**: `nuclei -u target.com -dast -t dast/vulnerabilities/sqli/`—SQLi payloads galore.
- **Pipeline It**: `subfinder -d target.com | httpx -silent | nuclei -t cves/ -s critical -j -o bugs.json`. Subdomains to vulns, automated.
- **Tags + Templates**: `nuclei -t http/ -tags "owasp-a7,rce" -u target.com`—XSS and RCE in one shot.
- **Cloud Hunting**: `nuclei -t cloud/aws/s3/ -tags aws -u target.com`—leaky buckets, incoming.

---

## Real-World Example: From Zero to Bug

Say you’re hunting on `target.com`:
1. Scope it: `nuclei -u target.com -t http/cves/ -s critical`.
2. Dig deeper: `nuclei -u target.com -t dast/ -tags sqli -dast -fa high`.
3. Export: `nuclei -u target.com -t exposures/ -tags secrets -j -o leaks.json`.
4. Chain it: `echo "target.com" | nuclei -w workflows/ -o results.txt`.

Found an SSRF in `dast/vulnerabilities/ssrf/`? That’s a potential bounty waiting for you.

---

## Conclusion: Time to Break Things

Nuclei’s your go-to tool, flexible, and packed with community. Master the flags (`nuclei -h`), explore `nuclei-templates/`, use those tags, and write your own YAMLs. You’ll be finding bugs while others are still googling. Big thanks to ProjectDiscovery for this amazing tool.
