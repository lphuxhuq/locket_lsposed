package com.locketx.module.hooks

import android.content.pm.ApplicationInfo
import android.util.Log
import com.locketx.module.ModuleEntry
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.lang.reflect.Executable
import java.lang.reflect.Method

/**
 * Everything a hook needs while the target package is being set up.
 */
class HookContext(
    val module: XposedModule,
    val packageName: String,
    val classLoader: ClassLoader,
    val applicationInfo: ApplicationInfo,
) {
    constructor(module: XposedModule, param: PackageReadyParam) : this(
        module = module,
        packageName = param.packageName,
        classLoader = param.classLoader,
        applicationInfo = param.applicationInfo,
    )

    fun log(msg: String) = module.log(Log.INFO, ModuleEntry.TAG, msg)

    fun warn(msg: String, t: Throwable? = null) {
        if (t == null) module.log(Log.WARN, ModuleEntry.TAG, msg)
        else module.log(Log.WARN, ModuleEntry.TAG, msg, t)
    }

    /** Loads a class from the app, returning null instead of throwing. */
    fun findClass(name: String): Class<*>? = try {
        Class.forName(name, false, classLoader)
    } catch (t: Throwable) {
        warn("class not found: $name")
        null
    }

    /**
     * Finds a method by name and parameter types, walking up the superclass
     * chain because the app may inherit it rather than declare it.
     */
    fun findMethod(clazz: Class<*>, name: String, vararg params: Class<*>): Method? {
        var c: Class<*>? = clazz
        while (c != null) {
            try {
                return c.getDeclaredMethod(name, *params)
            } catch (_: NoSuchMethodException) {
                c = c.superclass
            }
        }
        warn("method not found: ${clazz.name}.$name(${params.joinToString { it.simpleName }})")
        return null
    }

    /** Convenience: resolve a class and one of its methods in a single call. */
    fun findMethod(className: String, name: String, vararg params: Class<*>): Executable? =
        findClass(className)?.let { findMethod(it, name, *params) }
}
