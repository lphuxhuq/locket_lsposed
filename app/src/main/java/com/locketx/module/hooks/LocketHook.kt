package com.locketx.module.hooks

import io.github.libxposed.api.XposedInterface.Hooker
import io.github.libxposed.api.XposedModule
import java.lang.reflect.Executable

/**
 * One hook site.
 *
 * Split deliberately into two halves so the module survives a hot reload:
 *
 *  - [resolve] needs the app classloader, so it can only run during
 *    `onPackageReady`.
 *  - [hooker] is pure interception logic with no classloader dependency, so the
 *    new generation can rebuild it and hand it to
 *    `HookHandle.replaceHook()` without any package callback being replayed.
 *
 * [id] must stay stable across module versions - it is what links an old hook
 * handle back to its replacement after a hot reload.
 */
interface LocketHook {

    /** Stable, unique identifier for this hook site. */
    val id: String

    /** Locates the method/constructor to hook, or null if it is absent. */
    fun resolve(ctx: HookContext): Executable? = null

    /**
     * Locates every method/constructor this hook should attach to.
     *
     * Defaults to the single target from [resolve]. Override when one logical
     * hook must cover several methods (e.g. every overload, or a family of
     * React `@ReactMethod`s). All targets share this hook's [id]; that is fine -
     * hot reload looks a handle up by id and re-points each one at [hooker].
     */
    fun resolveAll(ctx: HookContext): List<Executable> = listOfNotNull(resolve(ctx))

    /** Builds the interception logic. Must not capture the app classloader. */
    fun hooker(module: XposedModule): Hooker
}
