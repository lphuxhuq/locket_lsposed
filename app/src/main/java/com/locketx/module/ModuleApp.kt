package com.locketx.module

import android.app.Application
import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Binds to the Xposed manager service on app start.
 *
 * [XposedServiceHelper] keeps a single static listener and caches binders that
 * arrive before one is registered, so registering in [Application.onCreate] is
 * both required and sufficient. Callbacks arrive on a binder thread.
 */
class ModuleApp : Application(), XposedServiceHelper.OnServiceListener {

    override fun onCreate() {
        super.onCreate()
        XposedServiceHelper.registerListener(this)
    }

    override fun onServiceBind(service: XposedService) = ServiceHolder.update(service)

    override fun onServiceDied(service: XposedService) = ServiceHolder.update(null)
}

/**
 * Process-wide holder for the bound service, so any screen can observe it.
 */
object ServiceHolder {

    fun interface Listener {
        fun onServiceChanged(service: XposedService?)
    }

    @Volatile
    var service: XposedService? = null
        private set

    private val listeners = CopyOnWriteArraySet<Listener>()

    internal fun update(service: XposedService?) {
        this.service = service
        listeners.forEach { it.onServiceChanged(service) }
    }

    fun addListener(listener: Listener, notifyImmediately: Boolean = true) {
        listeners.add(listener)
        if (notifyImmediately) listener.onServiceChanged(service)
    }

    fun removeListener(listener: Listener) = listeners.remove(listener)
}
