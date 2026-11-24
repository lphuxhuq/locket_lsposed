package com.locketx.module.hooks

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AutoPatchStateTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @Test
    fun sourceAndSchemaChangesInvalidateOnlyOwnedCaches() {
        val directory = temporary.newFolder("cache")
        val first = head(1)
        val initialized = AutoPatchState.observe(directory, "lx_gold_", "v9", first)
        assertTrue(initialized.initialized)
        assertFalse(initialized.changed)
        assertNull(initialized.previousHash)

        val same = AutoPatchState.observe(directory, "lx_gold_", "v9", first)
        assertFalse(same.initialized)
        assertFalse(same.changed)
        assertEquals(0, same.removedFiles)

        File(directory, "lx_gold_old.bundle").writeText("old")
        File(directory, "lx_gold_write.tmp").writeText("temp")
        val unrelated = File(directory, "account.db").apply { writeText("keep") }
        val second = AutoPatchState.observe(directory, "lx_gold_", "v9", head(2))
        assertTrue(second.changed)
        assertEquals(2, second.removedFiles)
        assertTrue(unrelated.isFile)

        File(directory, "lx_gold_schema.bundle").writeText("old-schema")
        val schema = AutoPatchState.observe(directory, "lx_gold_", "v10", head(2))
        assertTrue(schema.changed)
        assertEquals(1, schema.removedFiles)
    }

    private fun head(seed: Int): ByteArray {
        val value = ByteArray(HermesBundle.HEAD_SIZE)
        byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F)
            .copyInto(value)
        ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).putInt(8, 96).putInt(32, 4096)
        for (index in 12 until 32) value[index] = (seed + index).toByte()
        return value
    }
}
