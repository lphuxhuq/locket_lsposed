package com.locketx.module.hooks

import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Tracks the exact Hermes source seen by the loader.
 *
 * Android replaces and restarts an installed package during an APK update. On the first
 * bundle load after that restart, a new Hermes source hash moves this state forward and
 * removes only LocketX-owned stale bundle/cache files. The new bundle is then discovered
 * and patched by name; no app version code or byte offset participates in the decision.
 */
internal object AutoPatchState {
    data class Observation(
        val sourceHash: String,
        val initialized: Boolean,
        val changed: Boolean,
        val previousHash: String?,
        val removedFiles: Int,
    )

    private const val STATE_FILE = ".lx_gold_auto_patch"

    @Synchronized
    fun observe(
        directory: File,
        cachePrefix: String,
        schema: String,
        sourceHead: ByteArray,
    ): Observation {
        val sourceHash = requireNotNull(HermesBundle.sourceHashHex(sourceHead)) {
            "Unsupported Hermes bundle header"
        }
        check(directory.isDirectory || directory.mkdirs()) { "Cache directory unavailable" }

        val stateFile = File(directory, STATE_FILE)
        val previous = read(stateFile)
        val current = State(schema, sourceHash)
        if (previous == current) {
            return Observation(sourceHash, initialized = false, changed = false,
                previousHash = previous.sourceHash, removedFiles = 0)
        }

        var removed = 0
        directory.listFiles()?.forEach { file ->
            if (file.name.startsWith(cachePrefix) &&
                (file.name.endsWith(".bundle") || file.name.endsWith(".tmp")) &&
                file.delete()
            ) {
                removed++
            }
        }
        publish(stateFile, current)
        return Observation(
            sourceHash = sourceHash,
            initialized = previous == null,
            changed = previous != null,
            previousHash = previous?.sourceHash,
            removedFiles = removed,
        )
    }

    private data class State(val schema: String, val sourceHash: String)

    private fun read(file: File): State? = try {
        val lines = file.readLines(Charsets.US_ASCII)
        if (lines.size != 2 || lines[0].isBlank() ||
            lines[1].length != 40 || lines[1].any { it !in "0123456789abcdef" }
        ) null else State(lines[0], lines[1])
    } catch (_: Exception) {
        null
    }

    private fun publish(file: File, state: State) {
        val temporary = File.createTempFile("$STATE_FILE-", ".tmp", file.parentFile)
        try {
            FileOutputStream(temporary).use { stream ->
                stream.write("${state.schema}\n${state.sourceHash}\n".toByteArray(Charsets.US_ASCII))
                stream.fd.sync()
            }
            try {
                Files.move(temporary.toPath(), file.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temporary.delete()
        }
    }
}
