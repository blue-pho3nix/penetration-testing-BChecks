# Burp Suite BChecks for Pentesting

## Installation Instructions:
1. Open Burp Suite
2. CLick on `Extensions`
3. Click on `Bchecks`
4. Click on `+ New`
5. Choose Blank
6. Past in the BCheck Code Below

---

### Potential DOM XSS Sinks BCheck
![image](https://github.com/user-attachments/assets/58a20659-7da5-43db-b922-e1eee0d2bd1b)

#### Currently Finds:
- `document.write`
- `document.writeln`
- `document.domain`
- `.innerHTML`
- `.outerHTML`
- `.insertAdjacentHTML`
- `<iframe srcdoc>`
- `eval`
- `setTimeout`
- `setInterval`
- `DOMParser.parseFromString`
- `.onevent`
- `new Function`

#### BCheck Code:
```
metadata:
    language: v1-beta
    name: "Potential DOM XSS Sinks"
    author: "Jackie Friedberg"
    description: "Identifies potential DOM XSS sinks in responses."
    tags: "passive"

given response then
    if {latest.response} matches "(?i)document\.write\(|(?i)document\.writeln\(|(?i)document\.domain|(?i)\.innerHTML|(?i)\.outerHTML|(?i)\.insertAdjacentHTML|(?i)<iframe\s+srcdoc|(?i)eval\(|(?i)setTimeout\(|(?i)setInterval\(|(?i)DOMParser\.parseFromString|(?i)\.onevent" then
        report issue:
            severity: high
            confidence: firm
            detail: "Potential DOM XSS sink detected in the response."
    end if
```

#### References:
- https://portswigger.net/web-security/cross-site-scripting/dom-based
- https://web.dev/articles/trusted-types

---
