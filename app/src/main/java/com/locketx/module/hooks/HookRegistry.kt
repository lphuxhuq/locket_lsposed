package com.locketx.module.hooks

import io.github.libxposed.api.XposedInterface.HookHandle
import io.github.libxposed.api.XposedModule

/**
 * The single place where hooks are declared.
 *
 * To add a hook: write a [LocketHook] and add it to [hooks]. Nothing else changes.
 */
object HookRegistry {

    private val hooks: List<LocketHook> = listOf(
        // Deterministic Gold unlock: patch the Hermes bundle at load.
        BundlePatchHook,
        // Gold badge, granted to the signed-in user only (never to friends).
        FirestoreBadgeHook,
    )

    val size: Int get() = hooks.size

    private fun byId(id: String?): LocketHook? =
        if (id == null) null else hooks.firstOrNull { it.id == id }

    /**
     * Installs every hook. One failing hook never takes down the others - a
     * module that throws here would leave the target app half-hooked.
     *
     * @return how many hooks were installed successfully.
     */
    fun installAll(ctx: HookContext): Int {
        var installed = 0
        for (hook in hooks) {
            try {
                val targets = hook.resolveAll(ctx)
                if (targets.isEmpty()) {
                    ctx.warn("skipping [${hook.id}]: target not found")
                    continue
                }
                for (target in targets) {
                    try {
                        ctx.module.hook(target)
                            // The id is what lets a hot reload reconnect this handle
                            // to its replacement later. API 102+. Several targets may
                            // share one id; hot reload re-points each handle by id.
                            .setId(hook.id)
                            .intercept(hook.hooker(ctx.module))
                        ctx.log("hooked [${hook.id}] -> ${target.declaringClass.name}.${target.name}")
                        installed++
                    } catch (t: Throwable) {
                        ctx.warn("failed to install [${hook.id}] on ${target.name}", t)
                    }
                }
            } catch (t: Throwable) {
                ctx.warn("failed to install [${hook.id}]", t)
            }
        }
        return installed
    }

    /**
     * Rebuilds hooks after a hot reload.
     *
     * Package callbacks are NOT replayed for a new generation, so the old
     * handles are the only link to what was hooked. Each handle is atomically
     * re-pointed at the new code via [HookHandle.replaceHook]; anything the new
     * version no longer declares is unhooked instead.
     */
    fun reinstallAfterHotReload(module: XposedModule, oldHandles: List<HookHandle>): Int {
        var replaced = 0
        for (handle in oldHandles) {
            try {
                val hook = byId(handle.id)
                if (hook == null) {
                    handle.unhook()
                    continue
                }
                handle.replaceHook(hook.hooker(module))
                replaced++
            } catch (t: Throwable) {
                module.log(android.util.Log.WARN, com.locketx.module.ModuleEntry.TAG,
                    "hot reload: failed to replace ${handle.id}", t)
            }
        }
        return replaced
    }
}
