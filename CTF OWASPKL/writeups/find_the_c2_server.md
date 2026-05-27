# Find the C2 Server - Writeup

## Challenge Description
We are given a malicious APK file (`malapk.apk`) that secretly communicates with a C2 (Command and Control) server. The goal is to identify the C2 Server address and retrieve the flag.

## Solution Steps

### 1. Static Analysis of the APK
Using tools like `dex2jar`, `jadx`, or basic string extraction over the `classes.dex` files within the APK, we searched for HTTP URLs and keywords. We identified a potential domain: `https://appsecmy.com/`.

Further analysis of the decompiled code (specifically `com.example.protonx1337.MainActivity`) reveals a method named `backdoorC2()`. 

### 2. Identifying the C2 Endpoint
Inside the `backdoorC2()` function, the application attempts to exfiltrate stolen device and session data. The destination URL is constructed by concatenating two strings found in `LiveLiterals$MainActivityKt.java`:
1. `d1` = `"https://appsecmy.com/"`
2. `d2` = `"pages/liga-ctf-2026"`

Therefore, the full C2 server endpoint the malware uses to drop its payload is:
`https://appsecmy.com/pages/liga-ctf-2026`

### 3. Fetching the Flag
We visited the C2 Server URL using standard web requests to see what was hosted at the endpoint. The page hosts information about "LIGA CTF 2026", but viewing the raw HTML source reveals a hidden comment near the bottom of the document:

```html
<!-- OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p} This is the FL4G. But feel free to join our Community Group-->
```

## Flag
`OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p}`
