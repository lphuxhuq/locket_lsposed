package com.locketx.module.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.locketx.module.ModuleEntry
import com.locketx.module.R
import com.locketx.module.ServiceHolder
import io.github.libxposed.service.XposedService

/**
 * Status screen: shows whether a framework is actually present and what it
 * supports. This is the fastest way to tell "module not activated" apart from
 * "module active but hooks did not match".
 */
class MainActivity : Activity(), ServiceHolder.Listener {

    private lateinit var status: TextView
    private lateinit var details: TextView
    private lateinit var scope: TextView
    private lateinit var requestScopeBtn: Button
    private lateinit var hotReloadBtn: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        details = findViewById(R.id.details)
        scope = findViewById(R.id.scope)
        requestScopeBtn = findViewById(R.id.request_scope)
        hotReloadBtn = findViewById(R.id.hot_reload)
        status.text = getString(R.string.status_checking)
    }

    override fun onStart() {
        super.onStart()
        ServiceHolder.addListener(this)
    }

    override fun onStop() {
        ServiceHolder.removeListener(this)
        super.onStop()
    }

    // Called on a binder thread - always hop to the UI thread.
    override fun onServiceChanged(service: XposedService?) = runOnUiThread {
        if (service == null) render(null) else renderBound(service)
    }

    private fun render(text: String?) {
        status.text = text ?: getString(R.string.status_inactive)
        details.text = getString(R.string.compatibility_profile)
        scope.text = ""
        requestScopeBtn.isEnabled = false
        hotReloadBtn.isEnabled = false
    }

    private fun renderBound(service: XposedService) = try {
        status.text = getString(R.string.status_active)
        val caps = buildList {
            if (service.frameworkProperties and XposedService.PROP_CAP_SYSTEM != 0L) add("SYSTEM")
            if (service.frameworkProperties and XposedService.PROP_CAP_REMOTE != 0L) add("REMOTE")
            if (service.frameworkProperties and XposedService.PROP_RT_API_PROTECTION != 0L) add("API_PROTECTION")
        }
        details.text = buildString {
            appendLine(getString(R.string.compatibility_profile))
            appendLine("Framework: ${service.frameworkName} ${service.frameworkVersion}")
            appendLine("Version code: ${service.frameworkVersionCode}")
            appendLine("API: ${service.apiVersion}")
            append("Capabilities: ${caps.joinToString(", ").ifEmpty { "none" }}")
        }
        scope.text = getString(R.string.scope_fmt, service.scope.joinToString(", ").ifEmpty { "(empty)" })

        requestScopeBtn.isEnabled = true
        requestScopeBtn.setOnClickListener { requestScope(service) }

        // getRunningTargets()/hotReloadModule() are API 102 only, and the
        // service throws rather than silently failing below that.
        hotReloadBtn.isEnabled = service.apiVersion >= XposedService.API_102
        hotReloadBtn.setOnClickListener { hotReload(service) }
    } catch (t: Throwable) {
        render("Error: ${t.message}")
    }

    private fun requestScope(service: XposedService) {
        service.requestScope(listOf(ModuleEntry.TARGET_PACKAGE), object : XposedService.OnScopeEventListener {
            override fun onScopeRequestApproved(approved: List<String>) = runOnUiThread {
                toast("Scope approved: $approved")
                renderBound(service)
            }

            override fun onScopeRequestFailed(message: String) = runOnUiThread {
                toast("Scope request failed: $message")
            }
        })
    }

    private fun hotReload(service: XposedService) = try {
        val targets = service.runningTargets
        if (targets.isEmpty()) {
            toast("No running target process to reload")
        } else {
            targets.forEach { target ->
                service.hotReloadModule(target, null) { t, result ->
                    runOnUiThread { toast("${t.processName}: ${result.status()}") }
                }
            }
        }
    } catch (t: Throwable) {
        toast("Hot reload failed: ${t.message}")
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
