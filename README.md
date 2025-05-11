# Burp Suite BChecks for Penetration Testing

## Installation Instructions:
1. Open Burp Suite
2. CLick on `Extensions`
3. Click on `Bchecks`

##### COPY/PASTE
4. Click on `+ New`
5. Choose `Blank`
6. Paste in the BCheck Code Below
7. Save

##### OR

##### IMPORT
4. Get the repo
```
git clone https://github.com/blue-pho3nix/penetration-testing-bchecks
```
5. Import .bcheck file(s)


---

### Potential DOM XSS Sinks BCheck
![image](https://github.com/user-attachments/assets/58a20659-7da5-43db-b922-e1eee0d2bd1b)

#### Currently Finds:
- `location.hash`
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

#### BCheck Code:
```
metadata:
    language: v2-beta
    name: "Potential DOM XSS Sinks"
    author: "Jackie Friedberg"
    description: "Identifies potential DOM XSS sinks in responses."
    tags: "passive"

given response
then
    if {latest.response} matches "(?i)document.write\(|document.writeln\(|document.domain|.innerHTML|.outerHTML|.insertAdjacentHTML|<iframe\s+srcdoc|eval\(|setTimeout\(|setInterval\(|DOMParser.parseFromString|\.on(?:click|load|mouseover|error|change|submit|focus|blur|keydown|keyup|keypress|mousedown|mouseup|mouseenter|mouseleave|mousemove|mouseout|reset|resize|scroll|select|unload|abort|beforeunload|hashchange|input|invalid|search|wheel|animationstart|animationend|animationiteration|transitionend|copy|cut|paste|dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|contextmenu)\s*(=|\(|setAttribute\s*\(\s*['\"]\s*(on[a-z]+)\s*['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\))"
    then
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
