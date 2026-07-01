---
name: hook-generation
description: Generate Frida and Xposed hook snippets for dynamic analysis of an Android APK.
---

# Hook Generation Workflow

Generate dynamic analysis hooks (Frida/Xposed) for intercepting method calls, modifying return values, and tracing execution in an Android APK.

## Workflow Steps

### Step 1: Identify Hook Targets

```bash
# Find entry points and lifecycle methods
jadx-ai navigate -t entry-points <apk>

# Find authentication-related methods
jadx-ai search -t method -q "login" <apk>
jadx-ai search -t method -q "authenticate" <apk>
jadx-ai search -t method -q "verify" <apk>
jadx-ai search -t method -q "check" <apk>

# Find crypto methods
jadx-ai search -t method -q "encrypt" <apk>
jadx-ai search -t method -q "decrypt" <apk>

# Find network methods
jadx-ai search -t method -q "execute" <apk>
jadx-ai search -t method -q "sendRequest" <apk>

# Find interesting classes
jadx-ai search -t class -q "Helper" <apk>
jadx-ai search -t class -q "Manager" <apk>
jadx-ai search -t class -q "Handler" <apk>
```

### Step 2: Analyze Target Methods

```bash
# Get class structure
jadx-ai class-detail -c <target-class> <apk>

# Decompile to understand parameters and return types
jadx-ai decompile -c <target-class> <apk>

# Get method signature details
jadx-ai decompile -c <target-class> -m <target-method> <apk>

# Check method usage
jadx-ai usage -c <target-class> -m <target-method> <apk>
```

### Step 3: Generate Frida Hooks

```bash
# Hook all methods in a class
jadx-ai hook -t frida -c <target-class> <apk>

# Hook specific method
jadx-ai hook -t frida -c <target-class> -m <target-method> <apk>

# Hook with overload specification (multiple overloads)
jadx-ai hook -t frida -c <target-class> -m <method-name> --with-overloads <apk>
```

**Output example:**
```javascript
// Frida hook for com.example.app.LoginActivity.authenticate
Java.perform(function() {
    var cls = Java.use("com.example.app.LoginActivity");
    cls.authenticate.overload("java.lang.String", "java.lang.String").implementation = function(username, password) {
        console.log("[*] authenticate called");
        console.log("    username: " + username);
        console.log("    password: " + password);
        var result = this.authenticate(username, password);
        console.log("    result: " + result);
        return result;
    };
});
```

### Step 4: Generate Xposed Hooks

```bash
# Hook all methods in a class
jadx-ai hook -t xposed -c <target-class> <apk>

# Hook specific method
jadx-ai hook -t xposed -c <target-class> -m <target-method> <apk>
```

### Step 5: Compose Complete Hook Script

Combine multiple hooks into a comprehensive Frida script:

```javascript
Java.perform(function() {
    // Hook 1: Login
    var loginCls = Java.use("com.example.app.LoginActivity");
    loginCls.authenticate.implementation = function(u, p) {
        console.log("[AUTH] Login attempt: " + u);
        return this.authenticate(u, p);
    };

    // Hook 2: Crypto
    var cipherCls = Java.use("javax.crypto.Cipher");
    cipherCls.getInstance.overload("java.lang.String").implementation = function(transformation) {
        console.log("[CRYPTO] Cipher.getInstance: " + transformation);
        return this.getInstance(transformation);
    };

    // Hook 3: Network
    var urlCls = Java.use("java.net.URL");
    urlCls.$init.overload("java.lang.String").implementation = function(url) {
        console.log("[NET] URL: " + url);
        return this.$init(url);
    };
});
```

### Step 6: Usage with Frida

```bash
# Attach to running app
frida -U -f com.example.app -l hooks.js --no-pause

# Spawn and attach
frida -U com.example.app -l hooks.js

# Output to file
frida -U com.example.app -l hooks.js -o output.log
```

## Common Hook Patterns

### Bypass root detection
```javascript
Java.perform(function() {
    // Hook common root detection methods
    var fileCls = Java.use("java.io.File");
    fileCls.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") >= 0 || path.indexOf("Supersu") >= 0) {
            console.log("[BYPASS] Root check bypassed: " + path);
            return false;
        }
        return this.exists();
    };
});
```

### Bypass SSL pinning
```javascript
Java.perform(function() {
    var trustManagerCls = Java.use("javax.net.ssl.X509TrustManager");
    var sslContextCls = Java.use("javax.net.ssl.SSLContext");
    // ... (full SSL unpinning script)
});
```

### Modify return values
```javascript
Java.perform(function() {
    var cls = Java.use("com.example.app.LicenseChecker");
    cls.isLicensed.implementation = function() {
        console.log("[HOOK] isLicensed → true");
        return true;  // Force return true
    };
});
```
