# LocketX

Modern LSPosed module for `com.locket.Locket`, built on libxposed API 102.

> **src TuanMeta**

## Auto-patch

LocketX intercepts both React Native bridge loaders and bridgeless `ReactInstance` loaders. It reads the Hermes bundle actually selected by the installed APK, resolves target properties and functions by name/structure, then writes a validated patched copy into the app cache.

When Locket is updated:

1. Android restarts the target process.
2. LocketX reads the new bundle source hash.
3. A changed hash removes only stale `lx_gold_*` cache files.
4. The new bundle is discovered and patched without APK version codes or fixed byte offsets.
5. The patched HBC is fully walked again and its SHA-1 footer is regenerated before Hermes loads it.

Compatible updates using **Hermes bytecode v96** and the known semantic names are handled automatically. Unknown HBC versions or ambiguous/renamed targets fail closed and load the original bundle; LSPosed logs contain the exact reason.

## Supported loaders

- `CatalystInstanceImpl.loadScriptFromAssets/File`
- `CatalystInstanceImpl.jniLoadScriptFromAssets/File`
- `ReactInstance.loadJSBundleFromAssets/File`

## Requirements

- Android 8.0+
- LSPosed/libxposed framework API 102+
- Scope: `com.locket.Locket`

## Install

1. Install the LocketX APK.
2. Enable LocketX in LSPosed and select `com.locket.Locket` as scope.
3. Force-stop Locket and open it again. Hot reload alone cannot add newly introduced hook targets.

## Build

```bash
./gradlew --no-daemon :app:testDebugUnitTest :app:assembleRelease
```

Required toolchain: JDK 17, Android platform 37 and build-tools 37.0.0. Local signing values belong in ignored `keystore.properties`; without it, Gradle uses the machine's debug key.

Release output:

```text
app/build/outputs/apk/release/app-release.apk
```

## Update diagnostics

Filter LSPosed module logs for `LocketX`. A successful first load after an APK update includes:

```text
gold: APK bundle changed ... regenerating
gold: hbc=96 ... -> patched ...
gold: patched bundle loaded via ...
```

An unchanged APK reuses the validated cache:

```text
gold: reusing cached lx_gold_....bundle
```

## Repository safety

The repository excludes APKs, extracted proprietary bundles, local SDK paths, signing keys and credentials. CI compiles source and uploads a workflow artifact; release signing remains local unless repository secrets are configured explicitly.

## Credit

**src TuanMeta**
