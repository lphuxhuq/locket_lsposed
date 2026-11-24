package com.locketx.module.hooks

import android.util.Log
import com.locketx.module.ModuleEntry
import io.github.libxposed.api.XposedInterface.Hooker
import io.github.libxposed.api.XposedModule
import java.lang.reflect.Executable
import java.lang.reflect.Method

/**
 * Grants the Locket Gold badge to the signed-in user *only*.
 *
 * ## Why this is not a bundle patch
 *
 * In JS the badge is decided by `doesUserHaveGoldBadge(badge) { return badge === 'locket_gold' }`.
 * That helper is shared by every avatar renderer (`renderAvatarBadge`, the moment view,
 * `useCatchUpSender`) as well as by the user's own customization screen, and it only ever
 * receives a badge *value* - never whose badge it is. Forcing it to `true`, which is what the
 * module used to do, therefore lit the gold heart on every friend's avatar too.
 *
 * The badge is a property of the user document, so it is granted where that document is
 * decoded: the current user's record gets `badge = 'locket_gold'`, everyone else's is passed
 * through untouched, and the unpatched helper then does exactly the right thing on its own.
 * Nothing is written back to Firestore, so this stays local to this device - friends' apps are
 * unaffected either way.
 *
 * ## Where we intercept
 *
 * `@react-native-firebase`'s Firestore module hands JS a snapshot as a `WritableMap` shaped
 * `{ path, data, metadata, exists }`. Two code paths produce one - the `documentGet` promise
 * and the realtime `documentOnSnapshot` event - and both funnel through the small serializer
 * helpers on [DOC_MODULE]. Hooking those covers both; hooking only the promise would let the
 * next realtime snapshot overwrite the badge again.
 *
 * Those helpers are R8-renamed (`f`, `m`), so they are found by SHAPE - every declared method
 * on that class returning [WRITABLE_MAP] - never by name. The returned map is then classified
 * by its own keys rather than by which method produced it: `path` + `data` is a document,
 * `uid` + `providerData` is the signed-in user (that one comes from the auth module, and is
 * how we learn which document is ours).
 *
 * Everything here is reflective: React Native is not on the module's compile classpath, and
 * [hooker] must not capture the app classloader, so classes are resolved lazily from the
 * objects that actually arrive.
 */
object FirestoreBadgeHook : LocketHook {

    override val id = "firestore.badge"

    private const val DOC_MODULE =
        "io.invertase.firebase.firestore.ReactNativeFirebaseFirestoreDocumentModule"
    private const val AUTH_MODULE =
        "io.invertase.firebase.auth.ReactNativeFirebaseAuthModule"

    private const val WRITABLE_MAP = "com.facebook.react.bridge.WritableMap"
    private const val READABLE_MAP = "com.facebook.react.bridge.ReadableMap"
    private const val READABLE_ARRAY = "com.facebook.react.bridge.ReadableArray"
    private const val WRITABLE_NATIVE_MAP = "com.facebook.react.bridge.WritableNativeMap"

    /** Locket's own user collection; the current user's document is `users/<uid>`. */
    private const val USER_COLLECTION = "users"

    private const val KEY_BADGE = "badge"
    private const val GOLD_BADGE = "locket_gold"

    /**
     * The signed-in uid, learned from the auth module and read by the Firestore side.
     *
     * Written on the RN native-modules thread and read on whichever thread delivers a
     * snapshot, hence `@Volatile`. Null until the first auth map arrives; until then no
     * document can be identified as ours and every snapshot passes through untouched.
     */
    @Volatile
    private var uid: String? = null

    override fun resolveAll(ctx: HookContext): List<Executable> {
        val out = ArrayList<Executable>()
        out += mapReturningMethods(ctx, DOC_MODULE)
        out += mapReturningMethods(ctx, AUTH_MODULE)
        if (out.isEmpty()) ctx.warn("badge: no WritableMap serializers found - badge left alone")
        return out
    }

    /** Every declared method of [className] that returns a `WritableMap`. */
    private fun mapReturningMethods(ctx: HookContext, className: String): List<Method> {
        val cls = ctx.findClass(className) ?: return emptyList()
        val ms = cls.declaredMethods.filter { it.returnType.name == WRITABLE_MAP }
        if (ms.isEmpty()) ctx.warn("badge: ${cls.simpleName} declares no WritableMap method")
        return ms
    }

    override fun hooker(module: XposedModule) = Hooker { chain ->
        val result = chain.proceed()
        try {
            if (result != null) classify(result, module)
        } catch (t: Throwable) {
            // A badge is cosmetic; never let it break a Firestore read.
            module.log(Log.WARN, ModuleEntry.TAG, "badge: post-processing failed", t)
        }
        result
    }

    /**
     * Routes one returned map by its own keys: the auth user map teaches us the uid, a
     * document snapshot for that uid gets the badge, anything else is left alone.
     */
    private fun classify(map: Any, module: XposedModule) {
        if (isSignedInUser(map)) {
            val found = getString(map, "uid")
            val next = found?.takeIf { it.isNotEmpty() }
            if (uid != next) {
                uid = next
                module.log(Log.INFO, ModuleEntry.TAG, "badge: signed-in account changed")
            }
            return
        }
        val me = uid ?: return
        if (!hasKey(map, "path") || !hasKey(map, "data")) return
        if (getString(map, "path") != "$USER_COLLECTION/$me") return

        val data = getMap(map, "data") ?: return
        if (getString(data, KEY_BADGE) == GOLD_BADGE) return // already gold, nothing to do

        val patched = copyWithBadge(data) ?: return
        putMap(map, "data", patched)
        module.log(Log.INFO, ModuleEntry.TAG, "badge: granted gold badge on own user document")
    }

    /**
     * True for the auth module's *user* map, not merely any map carrying a `uid`.
     *
     * Hooking by shape catches every `WritableMap` the auth module builds, and
     * `multiFactorInfoToMap` also has a `uid` - the enrolled second factor's, not the
     * account's. `providerData` is present only on the real user map, so requiring both
     * keeps a multi-factor enrolment from being mistaken for the signed-in account.
     */
    private fun isSignedInUser(map: Any): Boolean =
        hasKey(map, "uid") && hasKey(map, "providerData")

    /**
     * Rebuilds [data] with `badge = 'locket_gold'`.
     *
     * A fresh map rather than an in-place edit: `WritableNativeMap.getMap()` hands back a
     * detached copy, so mutating it would change nothing, and merging then overwriting a key
     * that already exists is not reliable either. Copying every entry except `badge` and then
     * adding ours is the one form that is unambiguous.
     */
    private fun copyWithBadge(data: Any): Any? {
        val loader = data.javaClass.classLoader ?: return null
        val out = Class.forName(WRITABLE_NATIVE_MAP, false, loader).getDeclaredConstructor()
            .newInstance()
        val readableMap = Class.forName(READABLE_MAP, false, loader)
        val readableArray = Class.forName(READABLE_ARRAY, false, loader)

        val it = data.javaClass.getMethod("keySetIterator").invoke(data) ?: return null
        val hasNext = it.javaClass.getMethod("hasNextKey")
        val next = it.javaClass.getMethod("nextKey")
        while (hasNext.invoke(it) as Boolean) {
            val key = next.invoke(it) as? String ?: continue
            if (key == KEY_BADGE) continue
            when (typeOf(data, key)) {
                "Null" -> call(out, "putNull", arrayOf(String::class.java), key)
                "Boolean" -> call(out, "putBoolean", arrayOf(String::class.java, Boolean::class.javaPrimitiveType!!), key, get(data, "getBoolean", key))
                "Number" -> call(out, "putDouble", arrayOf(String::class.java, Double::class.javaPrimitiveType!!), key, get(data, "getDouble", key))
                "String" -> call(out, "putString", arrayOf(String::class.java, String::class.java), key, get(data, "getString", key))
                "Map" -> call(out, "putMap", arrayOf(String::class.java, readableMap), key, get(data, "getMap", key))
                "Array" -> call(out, "putArray", arrayOf(String::class.java, readableArray), key, get(data, "getArray", key))
                else -> return null // an unknown ReadableType means a silently lossy copy
            }
        }
        call(out, "putString", arrayOf(String::class.java, String::class.java), KEY_BADGE, GOLD_BADGE)
        return out
    }

    // ---- reflective ReadableMap access ------------------------------------------------

    private fun hasKey(map: Any, key: String): Boolean =
        map.javaClass.getMethod("hasKey", String::class.java).invoke(map, key) as? Boolean ?: false

    private fun getString(map: Any, key: String): String? =
        if (!hasKey(map, key)) null
        else map.javaClass.getMethod("getString", String::class.java).invoke(map, key) as? String

    private fun getMap(map: Any, key: String): Any? =
        map.javaClass.getMethod("getMap", String::class.java).invoke(map, key)

    private fun putMap(map: Any, key: String, value: Any) {
        val readableMap = Class.forName(READABLE_MAP, false, map.javaClass.classLoader)
        map.javaClass.getMethod("putMap", String::class.java, readableMap).invoke(map, key, value)
    }

    /** The `ReadableType` enum constant's name, e.g. `"String"`. */
    private fun typeOf(map: Any, key: String): String? {
        val t = map.javaClass.getMethod("getType", String::class.java).invoke(map, key)
        return (t as? Enum<*>)?.name
    }

    private fun get(map: Any, getter: String, key: String): Any? =
        map.javaClass.getMethod(getter, String::class.java).invoke(map, key)

    private fun call(target: Any, name: String, types: Array<Class<*>>, vararg args: Any?) {
        target.javaClass.getMethod(name, *types).invoke(target, *args)
    }
}
