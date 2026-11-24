package com.locketx.module.hooks

import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

internal object BundleCache {
    fun find(directory: File, stem: String, sourceHead: ByteArray): File? = try {
        val expectedHash = HermesBundle.sourceHashHex(sourceHead)
        if (expectedHash == null) null else {
            val file = File(directory, "$stem.bundle")
            val bytes = file.readBytes()
            if (HermesBundle.sourceHashHex(bytes) == expectedHash &&
                HermesBundle.recordedLength(sourceHead) == bytes.size.toLong() &&
                HermesBundle.recordedLength(bytes) == bytes.size.toLong() &&
                HermesBundle.checksumValid(bytes)) file else null
        }
    } catch (_: Exception) {
        null
    }

    @Synchronized
    fun publish(directory: File, stem: String, bytes: ByteArray): File {
        require(HermesBundle.checksumValid(bytes)) { "Refusing invalid HBC checksum" }
        check(directory.isDirectory || directory.mkdirs()) { "Cache directory unavailable" }
        val temporary = File.createTempFile("$stem-", ".tmp", directory)
        val output = File(directory, "$stem.bundle")
        try {
            FileOutputStream(temporary).use { stream ->
                stream.write(bytes)
                stream.fd.sync()
            }
            try {
                Files.move(temporary.toPath(), output.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
            return output
        } finally {
            temporary.delete()
        }
    }
}
