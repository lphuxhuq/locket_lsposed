package com.locketx.module.hooks

import android.content.Context
import android.content.res.AssetManager
import android.util.Log
import com.locketx.module.ModuleEntry
import io.github.libxposed.api.XposedInterface.Hooker
import io.github.libxposed.api.XposedModule
import java.io.File
import java.io.InputStream
import java.lang.reflect.Executable
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method

/**
 * Intercepts supported React Native script-loader signatures and supplies a validated
 * HBC v96 copy. Property reads, the feature resolver, and selected boolean rollout
 * getters are resolved from the loaded bundle, not from per-version file offsets.
 *
 * The supplied Locket 1.247.3 bundle is the compatibility fixture. Unknown bytecode,
 * ambiguous functions, non-boolean accessors, or a failed validation load the original.
 * Cache revision and source hash select the file; its complete footer digest is checked
 * before reuse. Publication uses unique temporary files and atomic replacement.
 * FirestoreBadgeHook handles only the current user's local badge representation.
 */
object BundlePatchHook : LocketHook {

    override val id = "bundle.gold"

    private val DELEGATE_CLASSES = listOf(
        "com.facebook.react.runtime.ReactInstance",
        "com.facebook.react.bridge.CatalystInstanceImpl",
    )

    // Bump when the patch set changes so stale cached bundles are regenerated.
    private const val CACHE_PREFIX = "lx_gold_"
    private const val CACHE_VER = "v9"

    override fun resolveAll(ctx: HookContext): List<Executable> {
        val out = ArrayList<Executable>()
        for (cn in DELEGATE_CLASSES) {
            val cls = ctx.findClass(cn) ?: continue
            val ms = cls.declaredMethods.filter {
                val parameters = it.parameterTypes
                if (it.returnType != Void.TYPE) false
                else when (it.name) {
                    "loadScriptFromAssets", "jniLoadScriptFromAssets" ->
                        parameters.contentEquals(arrayOf(AssetManager::class.java, String::class.java, Boolean::class.javaPrimitiveType))
                    "loadScriptFromFile", "jniLoadScriptFromFile" ->
                        parameters.contentEquals(arrayOf(String::class.java, String::class.java, Boolean::class.javaPrimitiveType))
                    "loadJSBundleFromAssets" ->
                        parameters.contentEquals(arrayOf(AssetManager::class.java, String::class.java))
                    "loadJSBundleFromFile" ->
                        parameters.contentEquals(arrayOf(String::class.java, String::class.java))
                    else -> false
                }
            }
            if (ms.isNotEmpty()) out.addAll(ms)
        }
        if (out.isEmpty()) ctx.warn("gold: no loadScript delegate methods found")
        return out
    }

    override fun hooker(module: XposedModule) = Hooker { chain ->
        val methodName = chain.executable.name
        module.log(Log.INFO, ModuleEntry.TAG, "gold: loader entered $methodName")
        val first = chain.args.getOrNull(0)
        if (first is String && File(first).name.startsWith(CACHE_PREFIX)) {
            return@Hooker chain.proceed()
        }
        val replacement = try {
            when (first) {
                is AssetManager -> {
                    val assetURL = chain.args.getOrNull(1) as? String
                    if (assetURL != null) patchFromAssets(first, assetURL, module) else null
                }
                is String -> patchFromFile(first, module)
                else -> null
            }
        } catch (error: Throwable) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: preparation failed, using original", error)
            null
        }
        if (replacement == null) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: no replacement for $methodName, using original")
            return@Hooker chain.proceed()
        }
        val sourceURL = chain.args.getOrNull(1) as? String
            ?: return@Hooker chain.proceed()
        val sync = chain.args.getOrNull(2) as? Boolean ?: false
        if (first is AssetManager) {
            val receiver = chain.thisObject ?: return@Hooker chain.proceed()
            val fileLoader = try {
                resolveFileLoader(receiver.javaClass, methodName)
            } catch (error: Throwable) {
                module.log(Log.WARN, ModuleEntry.TAG, "gold: cannot resolve file loader", error)
                null
            }
            if (fileLoader == null) {
                module.log(Log.WARN, ModuleEntry.TAG, "gold: matching file loader missing, using original")
                return@Hooker chain.proceed()
            }
            // After execution starts, a loader exception must propagate; retrying the
            // original script would run startup twice against a partially initialized VM.
            try {
                fileLoader.invoke(receiver, *replacementArgs(replacement.absolutePath, sourceURL, sync, fileLoader.parameterCount))
            } catch (error: InvocationTargetException) {
                module.log(Log.WARN, ModuleEntry.TAG, "gold: replacement loader failed; original not retried", error.targetException)
                throw error.targetException
            }
            module.log(Log.INFO, ModuleEntry.TAG, "gold: patched bundle loaded via $methodName")
            null
        } else {
            val result = chain.proceed(replacementArgs(replacement.absolutePath, sourceURL, sync, chain.executable.parameterCount))
            module.log(Log.INFO, ModuleEntry.TAG, "gold: patched bundle loaded via $methodName")
            result
        }
    }

    private fun replacementArgs(path: String, sourceURL: String, sync: Boolean, parameterCount: Int): Array<Any?> =
        if (parameterCount == 2) arrayOf(path, sourceURL) else arrayOf(path, sourceURL, sync)

    internal fun resolveFileLoader(delegate: Class<*>, entryName: String): Method? {
        val name = when (entryName) {
            "jniLoadScriptFromAssets" -> "jniLoadScriptFromFile"
            "loadJSBundleFromAssets" -> "loadJSBundleFromFile"
            else -> "loadScriptFromFile"
        }
        val signature = if (name == "loadJSBundleFromFile")
            arrayOf(String::class.java, String::class.java)
        else arrayOf(String::class.java, String::class.java, Boolean::class.javaPrimitiveType)
        var current: Class<*>? = delegate
        while (current != null) {
            val method = current.declaredMethods.firstOrNull {
                it.name == name && it.returnType == Void.TYPE &&
                    it.parameterTypes.contentEquals(signature)
            }
            if (method != null) {
                method.isAccessible = true
                return method
            }
            current = current.superclass
        }
        return null
    }

    private fun patchFromAssets(am: AssetManager, assetURL: String, module: XposedModule): File? {
        val assetName = assetURL.substringAfterLast("://").ifEmpty { assetURL }
        val orig = try {
            // The head alone says whether this build's patched bundle is already on disk,
            // which it is on every launch except the first after an app update. The asset
            // is STORED in the APK, so skipping it skips a straight ~10 MB copy.
            val head = ByteArray(HermesBundle.HEAD_SIZE)
            am.open(assetName).use { if (!fill(it, head)) return null }
            cached(head, module)?.let { return it }
            am.open(assetName).use { it.readBytes() }
        } catch (t: Throwable) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: cannot read bundle asset '$assetName'", t); return null
        }
        return patchBytes(orig, module)
    }

    private fun patchFromFile(fileName: String, module: XposedModule): File? {
        val f = File(fileName)
        if (!f.isFile) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: file loader input is not a readable file")
            return null
        }
        // Same head-first order as the asset path: these few bytes say both whether this is
        // an HBC v96 bundle at all and whether we have already patched it, so we never pull
        // ~10 MB in for a file we cannot use or have no work left on.
        val head = readHead(f) ?: run {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: file loader header is unreadable")
            return null
        }
        if (!HermesBundle.hasBundleHeader(head)) {
            module.log(Log.INFO, ModuleEntry.TAG, "gold: file loader input is not supported HBC v96")
            return null
        }
        cached(head, module)?.let { return it }
        val orig = try { f.readBytes() } catch (t: Throwable) { return null }
        return patchBytes(orig, module)
    }

    /**
     * Discover + patch [orig] in place, publish it to filesDir, return the cached file.
     * Both callers consult [cached] first, so reaching here means there is work to do.
     */
    private fun patchBytes(orig: ByteArray, module: XposedModule): File? {
        val sha = HermesBundle.sourceHashHex(orig)
        if (sha == null) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: not a supported HBC v96 bundle - left un-patched")
            return null
        }
        val filesDir = appFilesDir() ?: run {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: application files directory unavailable")
            return null
        }

        val report = HermesBundle.patchInPlace(orig)
        for (w in report.warnings) module.log(Log.WARN, ModuleEntry.TAG, "gold: $w")
        module.log(if (report.ok) Log.INFO else Log.WARN, ModuleEntry.TAG, report.summary)
        if (!report.ok) return null
        for (feature in report.appliedFeatures) {
            module.log(Log.INFO, ModuleEntry.TAG, "rollout: $feature")
        }

        return try {
            val stem = cacheStem(sha)
            // A source-hash key never repeats, so nothing would ever replace the previous
            // build's ~10 MB copy, nor a .tmp left behind by a killed write. Reap them here,
            // where we know which one is about to become the current one.
            filesDir.listFiles { c -> c.name.startsWith(CACHE_PREFIX) && !c.name.startsWith(stem) }
                ?.forEach { it.delete() }
            BundleCache.publish(filesDir, stem, orig)
        } catch (t: Throwable) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: patched bundle write failed", t); null
        }
    }

    /**
     * The patched copy of the bundle whose header is [head], or null when it still has to
     * be built. A cached file counts only if its own header carries the same source hash -
     * so name and content agree - and the file length the bundle records for itself, so a
     * truncated or damaged copy is rebuilt instead of being handed to Hermes.
     *
     * A hit is logged: patching never touches the header, so a cached file keeps the
     * original's source hash and a reused copy is otherwise indistinguishable in logcat
     * from a fresh patch. Saying so is what tells a stale cache (patch set changed but
     * [CACHE_VER] was not bumped) apart from a working one.
     */
    private fun cached(head: ByteArray, module: XposedModule): File? {
        val sha = HermesBundle.sourceHashHex(head) ?: return null
        val directory = appFilesDir() ?: return null
        val observation = try {
            AutoPatchState.observe(directory, CACHE_PREFIX, CACHE_VER, head)
        } catch (error: Throwable) {
            module.log(Log.WARN, ModuleEntry.TAG, "gold: auto-patch state update failed", error)
            return null
        }
        when {
            observation.initialized ->
                module.log(Log.INFO, ModuleEntry.TAG,
                    "gold: auto-patch initialized source=${sha.take(12)} schema=$CACHE_VER")
            observation.changed ->
                module.log(Log.INFO, ModuleEntry.TAG,
                    "gold: APK bundle changed ${observation.previousHash?.take(12)} -> ${sha.take(12)}; " +
                        "removed=${observation.removedFiles}, regenerating")
        }
        val out = BundleCache.find(directory, cacheStem(sha), head) ?: return null
        module.log(Log.INFO, ModuleEntry.TAG, "gold: reusing cached ${out.name}")
        return out
    }

    private fun cacheStem(sha: String) = "$CACHE_PREFIX${sha}_$CACHE_VER"

    /** The first [HermesBundle.HEAD_SIZE] bytes of [f], or null if it is shorter or unreadable. */
    private fun readHead(f: File): ByteArray? = try {
        val head = ByteArray(HermesBundle.HEAD_SIZE)
        f.inputStream().use { if (fill(it, head)) head else null }
    } catch (_: Throwable) {
        null
    }

    /**
     * Fills [buf] from [s]; false when the stream ends first. A single `read` may return
     * fewer bytes than asked for, and `readNBytes` would need API 33 - the module runs
     * from 26.
     */
    private fun fill(s: InputStream, buf: ByteArray): Boolean {
        var n = 0
        while (n < buf.size) {
            val r = s.read(buf, n, buf.size - n)
            if (r <= 0) return false
            n += r
        }
        return true
    }

    /** The target app's own files dir, via ActivityThread (we run in its process). */
    private fun appFilesDir(): File? = try {
        val at = Class.forName("android.app.ActivityThread")
        val app = at.getMethod("currentApplication").invoke(null) as? Context
        app?.filesDir ?: File("/data/data/${ModuleEntry.TARGET_PACKAGE}/files").takeIf { it.isDirectory }
    } catch (_: Throwable) {
        File("/data/data/${ModuleEntry.TARGET_PACKAGE}/files").takeIf { it.isDirectory }
    }
}
