package com.locketx.module.hooks

import java.security.MessageDigest

/**
 * Transactional, name/structure-driven HBC v96 patcher.
 *
 * Gold property reads load true; a unique feature-status resolver returns "enabled".
 * Only explicitly selected accessors that reference getBoolean are given boolean
 * return values. Configuration strings, numeric settings, authentication, abuse
 * handling, and other unrelated Remote Config keys are not blanket-overridden.
 *
 * Every function is decoded at instruction boundaries before mutation. Failed
 * validation leaves input unchanged. Successful edits preserve layout and refresh
 * the HBC footer SHA-1, while the original source hash remains the cache identity.
 */
internal class HermesBundle private constructor(private val b: ByteArray) {

    /** What [patchInPlace] did, in the form the hook logs. */
    class Report(
        /** True only when every gate passed and the bundle now holds the patched bytecode. */
        val ok: Boolean,
        /** One line for logcat: hash, table sizes, resolved ids, counts per category. */
        val summary: String,
        /** Non-fatal findings - a renamed getter, an unexpected count, a shared body. */
        val warnings: List<String>,
        val appliedFeatures: List<String> = emptyList(),
    )

    /** One bytecode edit: [offset] currently holds [orig]; overwrite it with [new]. */
    private class Site(
        val kind: String,
        val fn: Int,
        val offset: Int,
        val orig: ByteArray,
        val new: ByteArray,
    )

    /** Any gate failure. Caught in [patchInPlace], which then patches nothing. */
    private class Abort(message: String) : Exception(message)

    // ---- header / section layout -------------------------------------------------------

    private var functionCount = 0
    private var stringCount = 0
    private var stringStorageSize = 0
    private var fhOff = 0 // function headers
    private var stOff = 0 // small string table
    private var sgOff = 0 // string storage

    // ---- decoded tables ----------------------------------------------------------------

    private var fOff = IntArray(0)
    private var fSize = IntArray(0)
    private var fName = IntArray(0)
    private var largeHeaders = 0

    /** String-table ids per entry of [TARGETS]; empty when that name is absent. */
    private var ids: Array<IntArray> = emptyArray()

    // ---- discovery output --------------------------------------------------------------

    private val sites = ArrayList<Site>()
    private val warnings = ArrayList<String>()
    private val appliedFeatures = ArrayList<String>()
    private var instructions = 0

    // ====================================================================================
    // Pipeline
    // ====================================================================================

    private fun run(): Report {
        header()
        strings()
        functions()
        val gateCandidates = walk() // also collects the gold sites
        gateSite(gateCandidates)
        for (t in T_RC_FIRST until TARGETS.size) {
            val name = String(TARGETS[t], Charsets.US_ASCII)
            entryByName(KIND_RC, t, if (name in FALSE_GETTERS) FALSE_RET else TRUE_RET)
        }
        validate()
        apply()
        val broken = try {
            reWalk()
        } catch (t: Throwable) {
            t.message ?: t.javaClass.simpleName
        }
        if (broken != null) {
            restore()
            throw Abort("patched bundle no longer walks: $broken")
        }
        try {
            refreshChecksum(b)
        } catch (t: Throwable) {
            restore()
            throw t
        }
        return Report(true, summary("patched"), warnings, appliedFeatures.toList())
    }

    /** Header magic, bytecode version, counts, and the section offsets we need. */
    private fun header() {
        if (b.size < HEADER_SIZE) throw Abort("file is smaller than an HBC header")
        for (i in MAGIC.indices) if (b[i] != MAGIC[i]) throw Abort("not a Hermes bundle")
        val version = i32(8)
        if (version != HBC_VERSION) throw Abort("hbc version $version, expected $HBC_VERSION")

        val fileLength = count(32, "fileLength")
        functionCount = count(40, "functionCount")
        val stringKindCount = count(44, "stringKindCount")
        val identifierCount = count(48, "identifierCount")
        stringCount = count(52, "stringCount")
        val overflowStringCount = count(56, "overflowStringCount")
        stringStorageSize = count(60, "stringStorageSize")
        if (fileLength != b.size) throw Abort("fileLength $fileLength != file size ${b.size}")
        if (!checksumValid(b)) throw Abort("HBC footer SHA-1 mismatch")
        if (functionCount == 0 || stringCount == 0) throw Abort("empty function or string table")

        // Sections follow the header back to back, each padded to 4 bytes. Only the first
        // six matter here; stopping at string storage keeps us independent of the bigInt /
        // regExp / cjsModule entry sizes, which no bundle we have ever exercises. The sum
        // is kept in a Long so a hostile count cannot wrap it into a plausible offset.
        var o = HEADER_SIZE.toLong()
        fhOff = o.toInt(); o = align4(o + 16L * functionCount)
        o = align4(o + 4L * stringKindCount)
        o = align4(o + 4L * identifierCount)
        stOff = o.toInt(); o = align4(o + 4L * stringCount)
        o = align4(o + 8L * overflowStringCount)
        sgOff = o.toInt(); o = align4(o + stringStorageSize.toLong())
        // Checked after the assignments, which are only read once this returns.
        if (o > b.size) throw Abort("section table runs past the end of the file")
    }

    /**
     * Resolves [TARGETS] to string ids in one pass, comparing raw storage bytes.
     *
     * Every target is ASCII, so UTF-16 entries and overflowed ones (length 0xFF, which no
     * length bit can match) are skipped outright and the overflow table is never needed.
     * All matching ids are kept: Hermes uniques its string table, but nothing in the
     * format guarantees it.
     */
    private fun strings() {
        var lenMask = 0L
        for (t in TARGETS) lenMask = lenMask or (1L shl t.size)
        val out = Array(TARGETS.size) { IntArray(0) }
        for (i in 0 until stringCount) {
            val w = i32(stOff + 4 * i)
            if ((w and 1) != 0) continue // UTF-16 - never one of our ASCII names
            val len = (w ushr 24) and 0xFF
            if (len >= 64 || ((lenMask ushr len) and 1L) == 0L) continue
            val off = (w ushr 1) and 0x7FFFFF
            if (off > stringStorageSize - len) continue
            val base = sgOff + off
            val first = b[base]
            for (k in TARGETS.indices) {
                val t = TARGETS[k]
                if (t.size != len || t[0] != first) continue
                if (regionEquals(base, t)) {
                    out[k] = out[k] + i
                    break
                }
            }
        }
        ids = out
        if (out[T_GOLD].isEmpty()) throw Abort("string 'hasGoldSubscription' not found")
    }

    /**
     * Decodes every 16-byte function header into parallel arrays.
     *
     * Flag bit 5 means the record is only a pointer to a 31-byte header elsewhere in the
     * file - 11 functions per bundle take that path, `global` among them. Skipping it
     * would give those 11 a garbage range and the walk would abort the whole patch.
     */
    private fun functions() {
        val n = functionCount
        fOff = IntArray(n)
        fSize = IntArray(n)
        fName = IntArray(n)
        for (i in 0 until n) {
            val p = fhOff + 16 * i
            val w0 = i32(p)
            val w1 = i32(p + 4)
            val w2 = i32(p + 8)
            val w3 = i32(p + 12)
            var off = w0 and 0x1FFFFFF
            var size = w1 and 0x7FFF
            var name = (w1 ushr 15) and 0x1FFFF
            if (((((w3 ushr 24) and 0xFF) ushr 5) and 1) != 0) {
                val large = ((w2 and 0x1FFFFFF) shl 16) or (off and 0xFFFF)
                if (large < 0 || large > b.size - LARGE_HEADER_SIZE) {
                    throw Abort("fn#$i overflowed header out of range")
                }
                off = i32(large)
                size = i32(large + 8)
                name = i32(large + 12)
                largeHeaders++
            }
            if (off < 0 || size < 0 || off > b.size - size) throw Abort("fn#$i bytecode out of range")
            if (name < 0 || name >= stringCount) throw Abort("fn#$i name id out of range")
            fOff[i] = off
            fSize[i] = size
            fName[i] = name
        }
    }

    /**
     * Walks every function once: collects the gold sites, nominates gate candidates, and
     * proves the opcode table decodes this bundle exactly.
     *
     * No instruction is ever read at an unverified position: the length table advances the
     * cursor, and an instruction that would cross `offset + size` aborts - which is the
     * "the walk lands exactly on offset + size" gate, stated per instruction so a bad
     * length can never read past the function either.
     *
     * @return the indices of the functions that match the feature-gate signature.
     */
    private fun walk(): List<Int> {
        val gold = ids[T_GOLD]
        val enabled = ids[T_ENABLED]
        val disabled = ids[T_DISABLED]
        val subscriber = ids[T_SUBSCRIBER]
        val candidates = ArrayList<Int>()
        for (fn in 0 until functionCount) {
            val size = fSize[fn]
            if (size == 0) continue
            var pc = fOff[fn]
            val end = pc + size
            var sawEnabled = false
            var sawDisabled = false
            var sawSubscriber = false
            while (pc < end) {
                val op = b[pc].toInt() and 0xFF
                val len = opLen(op)
                if (len == 0) throw Abort("unknown opcode 0x${op.toString(16)} in fn#$fn")
                if (pc > end - len) throw Abort("fn#$fn: instruction at 0x${pc.toString(16)} crosses its end")
                when (op) {
                    OP_GET_BY_ID_SHORT -> if (gold.has(u8(pc + 4))) goldSite(fn, pc, len)
                    OP_GET_BY_ID, OP_TRY_GET_BY_ID -> if (gold.has(u16(pc + 4))) goldSite(fn, pc, len)
                    OP_GET_BY_ID_LONG, OP_TRY_GET_BY_ID_LONG -> if (gold.has(i32(pc + 4))) goldSite(fn, pc, len)
                    OP_LOAD_CONST_STRING, OP_LOAD_CONST_STRING_LONG -> {
                        val s = if (op == OP_LOAD_CONST_STRING) u16(pc + 2) else i32(pc + 2)
                        if (enabled.has(s)) sawEnabled = true
                        else if (disabled.has(s)) sawDisabled = true
                        else if (subscriber.has(s)) sawSubscriber = true
                    }
                }
                pc += len
                instructions++
            }
            if (sawEnabled && sawDisabled && sawSubscriber && size <= GATE_MAX_SIZE) candidates.add(fn)
        }
        return candidates
    }

    // ====================================================================================
    // Site construction
    // ====================================================================================

    /**
     * A `GetById`-family read of `'hasGoldSubscription'` at [pc]: fill its whole span with
     * `LoadConstTrue dst`, so the destination register holds `true` and the next
     * instruction still starts where it did. An odd span is squared off with `Mov dst,dst`
     * (v96 has no one-byte no-op). Only reads reach here; writes are never matched.
     */
    private fun goldSite(fn: Int, pc: Int, len: Int) {
        for (s in sites) if (s.offset == pc) return // same body reached through an alias
        val dst = b[pc + 1]
        val tail = if (len % 2 == 0) 0 else 3
        if (len < tail + 2) {
            warn("gold read at 0x${pc.toString(16)} is only $len bytes - skipped")
            return
        }
        val new = ByteArray(len)
        var i = 0
        while (i < len - tail) {
            new[i] = OP_LOAD_CONST_TRUE.toByte()
            new[i + 1] = dst
            i += 2
        }
        if (tail == 3) {
            new[i] = OP_MOV.toByte()
            new[i + 1] = dst
            new[i + 2] = dst
        }
        sites.add(Site(KIND_GOLD, fn, pc, b.copyOfRange(pc, pc + len), new))
    }

    /**
     * The feature-gate resolver: `getFeatureStatus` is minified to a two-letter name, so it
     * is identified by behaviour - the one small two-parameter function that loads all of
     * `'enabled'`, `'disabled'` and `'subscriber'`. Anything but a single candidate is left
     * alone: guessing here would rewrite an unrelated function.
     */
    private fun gateSite(candidates: List<Int>) {
        val unique = ArrayList<Int>()
        for (fn in candidates) {
            if (paramCount(fn) != GATE_PARAMS) continue
            var seen = false
            for (other in unique) if (fOff[other] == fOff[fn]) seen = true
            if (!seen) unique.add(fn)
        }
        if (unique.size != 1) {
            warn("feature gate: ${unique.size} candidates, expected 1 - gates left locked")
            return
        }
        val enabled = ids[T_ENABLED]
        if (enabled.isEmpty()) {
            warn("feature gate: string 'enabled' not found - gates left locked")
            return
        }
        val id = enabled[0]
        // LoadConstString takes a 16-bit id; a larger one needs the long form (6 bytes).
        val payload = if (id <= 0xFFFF) {
            byteArrayOf(
                OP_LOAD_CONST_STRING.toByte(), 0, (id and 0xFF).toByte(), ((id ushr 8) and 0xFF).toByte(),
                OP_RET.toByte(), 0,
            )
        } else {
            byteArrayOf(
                OP_LOAD_CONST_STRING_LONG.toByte(), 0, (id and 0xFF).toByte(), ((id ushr 8) and 0xFF).toByte(),
                ((id ushr 16) and 0xFF).toByte(), ((id ushr 24) and 0xFF).toByte(), OP_RET.toByte(), 0,
            )
        }
        entrySite(KIND_GATE, unique[0], payload)
    }

    /** Resolves one [TARGETS] entry to a single function by name and patches its entry. */
    private fun entryByName(kind: String, target: Int, payload: ByteArray) {
        val nameIds = ids[target]
        val name = String(TARGETS[target], Charsets.US_ASCII)
        if (nameIds.isEmpty()) {
            warn("$kind $name: name not in this bundle - skipped")
            return
        }
        var fn = -1
        var found = 0
        for (i in 0 until functionCount) {
            if (!nameIds.has(fName[i])) continue
            found++
            fn = i
        }
        if (found != 1) {
            warn("$kind $name: $found functions carry this name - skipped")
            return
        }
        if (kind == KIND_RC && !referencesBooleanGetter(fn)) {
            warn("$kind $name: not a getBoolean accessor - skipped")
            return
        }
        val before = sites.size
        entrySite(kind, fn, payload)
        if (sites.size > before) appliedFeatures.add("$name=${name !in FALSE_GETTERS}")
    }

    private fun referencesBooleanGetter(fn: Int): Boolean {
        var pc = fOff[fn]
        val end = pc + fSize[fn]
        val booleanIds = ids[T_GET_BOOLEAN]
        while (pc < end) {
            val op = u8(pc)
            val len = opLen(op)
            if (len == 0 || pc > end - len) return false
            val property = when (op) {
                OP_GET_BY_ID_SHORT -> u8(pc + 4)
                OP_GET_BY_ID, OP_TRY_GET_BY_ID -> u16(pc + 4)
                OP_GET_BY_ID_LONG, OP_TRY_GET_BY_ID_LONG -> i32(pc + 4)
                else -> -1
            }
            if (booleanIds.has(property)) return true
            pc += len
        }
        return false
    }

    /**
     * Overwrites a function's entry with [payload], padding to the first instruction
     * boundary at or after it so the replacement covers whole instructions. The padding
     * lands after an unconditional `Ret`, so it is dead code; it exists only so the
     * patched bundle still decodes end to end, which [reWalk] then checks.
     */
    private fun entrySite(kind: String, fn: Int, payload: ByteArray) {
        if (bodySharers(fn) != 1) {
            warn("$kind fn#$fn: bytecode shared with another function - skipped")
            return
        }
        val off = fOff[fn]
        val end = off + fSize[fn]
        var cover = 0
        var pc = off
        while (pc < end) {
            val len = opLen(b[pc].toInt() and 0xFF)
            if (len == 0) throw Abort("unknown opcode in fn#$fn")
            cover += len
            pc += len
            // A one-byte gap cannot be filled: v96 has no one-byte instruction to pad with.
            if (cover >= payload.size && cover - payload.size != 1) break
        }
        val gap = cover - payload.size
        if (gap < 0 || gap == 1) {
            warn("$kind fn#$fn: no instruction boundary for a ${payload.size}-byte patch - skipped")
            return
        }
        val new = ByteArray(cover)
        payload.copyInto(new)
        var i = payload.size
        if (gap % 2 == 1) {
            new[i++] = OP_MOV.toByte()
            new[i++] = 0
            new[i++] = 0
        }
        while (i < cover) {
            new[i++] = OP_LOAD_CONST_TRUE.toByte()
            new[i++] = 0
        }
        sites.add(Site(kind, fn, off, b.copyOfRange(off, off + cover), new))
    }

    // ====================================================================================
    // Gates, application, verification
    // ====================================================================================

    /** Everything that must hold before a single byte is written. */
    private fun validate() {
        sites.sortBy { it.offset }
        var prevEnd = -1
        for (s in sites) {
            if (s.orig.size != s.new.size) throw Abort("site 0x${s.offset.toString(16)} changes length")
            if (s.offset < fOff[s.fn] || s.offset > fOff[s.fn] + fSize[s.fn] - s.orig.size) {
                throw Abort("site 0x${s.offset.toString(16)} is outside fn#${s.fn}")
            }
            if (!regionEquals(s.offset, s.orig)) throw Abort("site 0x${s.offset.toString(16)} moved")
            if (s.offset < prevEnd) throw Abort("site 0x${s.offset.toString(16)} overlaps the previous one")
            prevEnd = s.offset + s.orig.size
        }
        val gold = countOf(KIND_GOLD)
        // 0 reads means the property was renamed or inlined away - the unlock is gone, so
        // load the original. Any other count is a normal release change (Locket adding or
        // dropping a gold-gated screen) and must NOT cost the user the unlock.
        if (gold == 0) throw Abort("no 'hasGoldSubscription' reads found")
        if (gold != GOLD_READS) warn("$gold gold reads, expected $GOLD_READS - Locket's UI changed")
        if (sites.isEmpty()) throw Abort("nothing to patch")
    }

    private fun apply() {
        for (s in sites) s.new.copyInto(b, s.offset)
    }

    private fun restore() {
        for (s in sites) s.orig.copyInto(b, s.offset)
    }

    /**
     * Re-walks the functions [apply] touched; null when they all still decode.
     *
     * A function none of whose bytes changed decodes exactly as it did in [walk], which
     * already proved every function in the bundle - so re-walking only the overlapped ones
     * is the same gate, not a weaker one, for a fraction of the work. The test is on the
     * byte range rather than on `Site.fn`, which keeps a body reached through several
     * function records covered too.
     */
    private fun reWalk(): String? {
        if (sites.isEmpty()) return null
        // validate() sorted the sites and proved they do not overlap, so the first and the
        // last of them bound every byte apply() wrote.
        val lo = sites[0].offset
        val hi = sites[sites.size - 1].let { it.offset + it.new.size }
        for (fn in 0 until functionCount) {
            val size = fSize[fn]
            if (size == 0) continue
            var pc = fOff[fn]
            val end = pc + size
            if (end <= lo || pc >= hi || !touched(pc, end)) continue
            while (pc < end) {
                val len = opLen(b[pc].toInt() and 0xFF)
                if (len == 0) return "unknown opcode in fn#$fn"
                if (pc > end - len) return "fn#$fn ends mid-instruction"
                pc += len
            }
        }
        return null
    }

    /** True when a patched span overlaps the byte range `[start, end)`. */
    private fun touched(start: Int, end: Int): Boolean {
        for (s in sites) if (s.offset < end && start < s.offset + s.new.size) return true
        return false
    }

    // ====================================================================================
    // Small helpers
    // ====================================================================================

    private fun summary(what: String): String {
        val rc = TARGETS.size - T_RC_FIRST
        var bytes = 0
        for (s in sites) bytes += s.new.size
        return "gold: hbc=$HBC_VERSION sha=${hex(b, 12, 4)} funcs=$functionCount strings=$stringCount " +
            "largeHdr=$largeHeaders instrs=$instructions strid(hasGoldSubscription)=${firstId(T_GOLD)} " +
            "strid(enabled)=${firstId(T_ENABLED)} sites gold=${countOf(KIND_GOLD)}/$GOLD_READS " +
            "gate=${countOf(KIND_GATE)}/1 rc=${countOf(KIND_RC)}/$rc " +
            "-> $what ${sites.size} sites, $bytes bytes"
    }

    private fun countOf(kind: String): Int {
        var n = 0
        for (s in sites) if (s.kind == kind) n++
        return n
    }

    private fun firstId(target: Int) = ids[target].firstOrNull() ?: -1

    private fun warn(message: String) {
        warnings.add(message)
    }

    /** How many function records point at this one's bytecode (Hermes dedups bodies). */
    private fun bodySharers(fn: Int): Int {
        val off = fOff[fn]
        var n = 0
        for (i in 0 until functionCount) if (fOff[i] == off) n++
        return n
    }

    private fun paramCount(fn: Int): Int {
        val p = fhOff + 16 * fn
        val w0 = i32(p)
        val flags = (i32(p + 12) ushr 24) and 0xFF
        if (((flags ushr 5) and 1) != 0) {
            // Overflowed header, already range-checked by functions(): +4 is paramCount.
            val large = ((i32(p + 8) and 0x1FFFFFF) shl 16) or (w0 and 0xFFFF)
            return i32(large + 4)
        }
        return (w0 ushr 25) and 0x7F
    }

    private fun count(o: Int, name: String): Int {
        val v = i32(o)
        if (v < 0) throw Abort("header field $name out of range")
        return v
    }

    /** Membership in a tiny id set, without boxing or allocating a collection. */
    private fun IntArray.has(v: Int): Boolean {
        for (x in this) if (x == v) return true
        return false
    }

    private fun regionEquals(at: Int, want: ByteArray): Boolean {
        if (at < 0 || at > b.size - want.size) return false
        for (i in want.indices) if (b[at + i] != want[i]) return false
        return true
    }

    private fun u8(o: Int) = b[o].toInt() and 0xFF

    private fun u16(o: Int) = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    private fun i32(o: Int) = le32(b, o)

    companion object {

        /**
         * Discovers the sites in [bundle] and patches them IN PLACE.
         *
         * On success the array holds the patched bytecode. On any failure it is restored
         * byte for byte, so the caller can always fall back to loading it unchanged.
         */
        fun patchInPlace(bundle: ByteArray): Report = try {
            HermesBundle(bundle).run()
        } catch (t: Throwable) {
            // Includes the Abort gates and any index that a malformed table could produce.
            Report(false, "gold: bundle left un-patched - ${t.message ?: t.javaClass.simpleName}", emptyList())
        }

        /** True when [head] (the first 12 bytes of a file) starts an HBC v96 bundle. */
        fun hasBundleHeader(head: ByteArray): Boolean {
            if (head.size < MAGIC.size + 4) return false
            for (i in MAGIC.indices) if (head[i] != MAGIC[i]) return false
            return le32(head, 8) == HBC_VERSION
        }

        /**
         * The bundle's own 20-byte source hash as hex, or null if [head] does not start an
         * HBC v96 bundle. It keys the cache: two builds can share a byte size, never a
         * hash. Only [HEAD_SIZE] bytes are read, so the caller can answer "have we already
         * patched this build?" without pulling in the ~10 MB the bundle actually is.
         */
        fun sourceHashHex(head: ByteArray): String? {
            if (head.size < HEAD_SIZE || !hasBundleHeader(head)) return null
            return hex(head, 12, 20)
        }

        /**
         * The length the bundle records for itself, or -1 when [head] is too short. A
         * cached copy whose size on disk disagrees with it was truncated or damaged and
         * must be rebuilt rather than handed to Hermes.
         */
        fun recordedLength(head: ByteArray): Long {
            if (head.size < HEAD_SIZE) return -1L
            return le32(head, 32).toLong() and 0xFFFFFFFFL
        }

        // ---- format constants ----------------------------------------------------------

        private const val HBC_VERSION = 96
        private const val HEADER_SIZE = 128
        private const val LARGE_HEADER_SIZE = 31

        /**
         * Magic, bytecode version, source hash and fileLength all live in the first 36
         * bytes - everything needed to identify a bundle and to vet a cached copy of it.
         * Not private: the hook reads exactly this many bytes before deciding to read more.
         */
        const val HEAD_SIZE = 36

        private val MAGIC = byteArrayOf(
            0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F,
        )

        // ---- opcodes (HBC v96) ---------------------------------------------------------

        private const val OP_MOV = 0x08
        private const val OP_GET_BY_ID_SHORT = 0x36
        private const val OP_GET_BY_ID = 0x37
        private const val OP_GET_BY_ID_LONG = 0x38
        private const val OP_TRY_GET_BY_ID = 0x39
        private const val OP_TRY_GET_BY_ID_LONG = 0x3A
        private const val OP_RET = 0x5C
        private const val OP_LOAD_CONST_STRING = 0x73
        private const val OP_LOAD_CONST_STRING_LONG = 0x74
        private const val OP_LOAD_CONST_TRUE = 0x78
        private const val OP_LOAD_CONST_FALSE = 0x79

        /**
         * Total byte length of every HBC v96 instruction, opcode 0..205, two hex digits
         * each. Generated from the v96 operand table as `1 + sum(operand sizes)`, where
         * Reg8/UInt8/Addr8 = 1, UInt16 = 2, Reg32/UInt32/Addr32/Imm32 = 4, Double = 8.
         * An opcode past the end, or a zero, is unknown and aborts the walk - we never
         * guess a length. Validated against the supplied 1.247.3 bundle: 58,005 functions, with
         * every walk landing exactly on its end and no unknown opcodes.
         *
         * Note `SwitchImm` (0x85, 18 bytes) appends its jump table AFTER the function's
         * byte size, in the padding before the next function, so a plain bounded walk is
         * correct and must not try to skip it.
         */
        private const val OP_LEN_HEX =
            "010a0e0203080a04030903030303040404040404040404040404040404040404" + // 0x00
                "0404040404030304040304050405040502020207050505060806080608060804" + // 0x20
                "0507050704070505070404040605060404040505060707070704070302020402" + // 0x40
                "030101030507050705070404030603060a040604060202020202020302030303" + // 0x60
                "030403020e120103010507030403020503060306030602050407040704070407" + // 0x80
                "0407040704070407040704070407040704070407040704070407040704070407" + // 0xa0
                "0404040404040404040404040404" // 0xc0..0xcd

        private val OP_LEN = ByteArray(OP_LEN_HEX.length / 2) {
            OP_LEN_HEX.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }

        private fun opLen(op: Int) = if (op < OP_LEN.size) OP_LEN[op].toInt() else 0

        // ---- what we look for ----------------------------------------------------------

        private const val KIND_GOLD = "gold"
        private const val KIND_GATE = "gate"
        private const val KIND_RC = "rc"

        /** The six reads observed in Locket 1.247.3: FeatureGatesProvider, AccountManagementSheet, HasGoldSubscription, PaywallScreen, LocketGoldButton. */
        private const val GOLD_READS = 6

        /** The gate resolver is tiny and takes (feature, gateMap); both narrow the signature. */
        private const val GATE_MAX_SIZE = 128
        private const val GATE_PARAMS = 2

        private const val T_GOLD = 0
        private const val T_DISABLED = 1
        private const val T_SUBSCRIBER = 2
        private const val T_ENABLED = 3

        /** [TARGETS] from here on are Remote Config getters: optional, one function each. */
        private const val T_GET_BOOLEAN = 4
        private const val T_RC_FIRST = 5

        /**
         * Every name resolved at runtime. Order matters: [T_GOLD] .. [T_RC_FIRST] index it.
         *
         * Deliberately absent: `androidGoldSubscriptionOverride` (redundant with the gold
         * patch), `androidMusicCaptionEnabled` (not a Remote Config getter, and it gates an
         * unimplemented Spotify flow), and `doesUserHaveGoldBadge` - forcing that one true
         * lit the gold heart on EVERY avatar, friends included, because it only ever sees a
         * badge value and never whose badge it is. The badge is granted per-user instead, in
         * [FirestoreBadgeHook].
         */
        private val TARGETS: Array<ByteArray> = arrayOf(
            ascii("hasGoldSubscription"),
            ascii("disabled"),
            ascii("subscriber"),
            ascii("enabled"),
            ascii("getBoolean"),
            ascii("androidMusicCaptionSendEnabled"),
            ascii("androidCatchUpEnabled"),
            ascii("androidVideoPlayerEnabled"),
            ascii("androidRollcallEnabled"),
            ascii("androidRollcallNotificationsV2Enabled"),
            ascii("androidCameraRollHomePreviewEnabled"),
            ascii("androidBackgroundBlurEnabled"),
            ascii("androidUnsendMessageEnabled"),
            ascii("androidHistoryFriendCardEnabled"),
            ascii("androidCopyLinkEnabled"),
            ascii("androidOrientationRotationEnabled"),
            ascii("androidHapticsEnabled"),
            ascii("androidHistoryAdsEnabled"),
            ascii("androidHistoryAdsReportingEnabled"),
        )

        private val FALSE_GETTERS = setOf(
            "androidHistoryAdsEnabled",
            "androidHistoryAdsReportingEnabled",
        )

        /** `LoadConstTrue r0; Ret r0` - the whole body of a forced-true getter. */
        private val TRUE_RET = byteArrayOf(
            OP_LOAD_CONST_TRUE.toByte(), 0, OP_RET.toByte(), 0,
        )

        private val FALSE_RET = byteArrayOf(
            OP_LOAD_CONST_FALSE.toByte(), 0, OP_RET.toByte(), 0,
        )

        fun checksumValid(bundle: ByteArray): Boolean {
            if (bundle.size < HEADER_SIZE + 20) return false
            val digest = MessageDigest.getInstance("SHA-1")
            digest.update(bundle, 0, bundle.size - 20)
            return MessageDigest.isEqual(digest.digest(), bundle.copyOfRange(bundle.size - 20, bundle.size))
        }

        private fun refreshChecksum(bundle: ByteArray) {
            val digest = MessageDigest.getInstance("SHA-1")
            digest.update(bundle, 0, bundle.size - 20)
            digest.digest().copyInto(bundle, bundle.size - 20)
        }

        // ---- primitives ----------------------------------------------------------------

        private fun ascii(s: String) = s.toByteArray(Charsets.US_ASCII)

        private fun align4(x: Long) = (x + 3L) and 3L.inv()

        /** Little-endian u32 as a JVM Int; callers that use it as an offset check `>= 0`. */
        private fun le32(a: ByteArray, o: Int) =
            (a[o].toInt() and 0xFF) or
                ((a[o + 1].toInt() and 0xFF) shl 8) or
                ((a[o + 2].toInt() and 0xFF) shl 16) or
                ((a[o + 3].toInt() and 0xFF) shl 24)

        private fun hex(a: ByteArray, off: Int, len: Int): String {
            val sb = StringBuilder(len * 2)
            for (i in 0 until len) {
                val v = a[off + i].toInt() and 0xFF
                sb.append(HEX[v ushr 4]).append(HEX[v and 0xF])
            }
            return sb.toString()
        }

        private const val HEX = "0123456789abcdef"
    }
}
