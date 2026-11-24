package com.locketx.module

import android.util.Log
import com.locketx.module.hooks.HookContext
import com.locketx.module.hooks.HookRegistry
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.HotReloadedParam
import io.github.libxposed.api.XposedModuleInterface.HotReloadingParam
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam

/**
 * The module entry point.
 *
 * Registered in `src/main/resources/META-INF/xposed/java_init.list`. The framework
 * instantiates this class through its no-arg constructor and attaches itself
 * afterwards, so do no work in the constructor - start in [onModuleLoaded].
 *
 * Keeping exactly ONE entry class is what makes the module hot-reloadable.
 */
class ModuleEntry : XposedModule() {

    companion object {
        const val TAG = "LocketX"

        /** The app this module hooks. Must match META-INF/xposed/scope.list. */
        const val TARGET_PACKAGE = "com.locket.Locket"
    }

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        log(Log.INFO, TAG, "loaded into ${param.processName}")
    }

    /**
     * Fired once per package loaded in this process, after the app classloader exists.
     *
     * A process can host more than one package (sharedUserId,
     * `createPackageContext`), so always filter by package name instead of
     * assuming only the target arrives here.
     */
    override fun onPackageReady(param: PackageReadyParam) {
        if (param.packageName != TARGET_PACKAGE) return

        val installed = HookRegistry.installAll(HookContext(this, param))
        log(Log.INFO, TAG, "installed $installed targets from ${HookRegistry.size} hooks")

        // NOTE: detach() stops *all* later lifecycle callbacks for this entry,
        // onHotReloading included. Do not call it here or hot reload dies.
    }

    // ---- Hot reload ---------------------------------------------------------
    // onHotReloading runs in the OLD generation, onHotReloaded in the NEW one.

    override fun onHotReloading(param: HotReloadingParam): Boolean {
        log(Log.INFO, TAG, "hot reload requested")
        // Only classloader-neutral values may cross the generation boundary;
        // anything created by the old module classloader is rejected.
        param.setSavedInstanceState(System.currentTimeMillis())
        // Returning true retires this generation. Stop module-owned threads and
        // release module references here before doing so.
        return true
    }

    override fun onHotReloaded(param: HotReloadedParam) {
        val old = param.oldHookHandles
        log(Log.INFO, TAG, "hot reloaded in ${param.processName}, ${old.size} old hooks")

        // Package callbacks are NOT replayed, so the old handles are the only
        // link to what was hooked - re-point them at the new code rather than
        // unhooking, which would leave the module installed but inert.
        val replaced = HookRegistry.reinstallAfterHotReload(this, old)
        log(Log.INFO, TAG, "hot reload: replaced $replaced/${old.size} hooks")
    }
}
