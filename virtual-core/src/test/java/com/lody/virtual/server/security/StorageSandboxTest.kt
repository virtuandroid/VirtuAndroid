package com.lody.virtual.server.security

import com.lody.virtual.server.security.StorageSandbox.Companion.READ_WRITE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private typealias Op = (StorageSandbox.RuleList) -> StorageSandbox.RuleList

private fun allow(path: String): Op = { StorageSandbox.setFlag(path, it, READ_WRITE) }
private fun block(path: String): Op = { StorageSandbox.blocklist(path, it) }

/** Builds a fresh rule tree by applying [ops] in order. */
private fun sandbox(vararg ops: Op): StorageSandbox.RuleList =
    ops.fold(StorageSandbox.RuleList()) { rule, op -> op(rule) }

private fun StorageSandbox.RuleList.assertAllowed(vararg paths: String) =
    paths.forEach {
        val redirectPath = StorageSandbox.getRedirectPath(it, emptyMap())
        assertTrue("Expected ALLOWED: '$it'", StorageSandbox.isPathAllowed(redirectPath, this))
    }

private fun StorageSandbox.RuleList.assertDenied(vararg paths: String) =
    paths.forEach {
        val redirectPath = StorageSandbox.getRedirectPath(it, emptyMap())
        assertFalse("Expected DENIED: '$it'", StorageSandbox.isPathAllowed(redirectPath, this))
    }

/**
 * A path is only allowed if the deepest rule is ALLOW
 *
 * 1. All paths are blocked by default.
 * 2. Specific directories can be whitelisted
 * 3. Specific directories can be blocklisted, to block
 *    specific subdirectories in an otherwise whitelisted directory
 *
 * NOTE: Files and directories are functionally identical.
 * This is because some syscalls interact with directories as if they were files.
 */
// TODO Redirection tests!
class StorageSandboxTest {

    // ---------------------------------------------------------------
    // Defaults
    // ---------------------------------------------------------------

    @Test
    fun defaults_everythingDeniedWithNoRules() {
        sandbox().assertDenied(
            "/", "", "/home", "/home/", "/home/test/example", "relative/path"
        )
    }

    @Test
    fun defaults_emptyPathDeniedEvenWhenRootWhitelisted() {
        sandbox(allow("/")).assertDenied("")
    }

    // ---------------------------------------------------------------
    // File whitelist (exact match)
    // ---------------------------------------------------------------

    @Test
    fun fileWhitelist_exactPathAllowed() {
        sandbox(allow("/home/test/example")).assertAllowed("/home/test/example")
    }

    @Test
    fun fileWhitelist_trailingSlashVariantAllowed() {
        sandbox(allow("/home/test/example")).assertAllowed("/home/test/example/")
    }

    @Test
    fun fileWhitelist_parentAllowed() {
        val rules = sandbox(allow("/data/data/io.va.exposed64"))
        rules.assertAllowed(
            "/data",
            "/data/",
            "/data/data",
        )
        rules.assertDenied(
            "/root",
            "/root/",
            "/data/app",
            "/data/data/com.example.app"
        )
    }

    @Test
    fun fileWhitelist_childrenAllowed() {
        sandbox(allow("/home/test/example")).assertAllowed(
            "/home/test/example/test",
            "/home/test/example/a/b/c"
        )
    }

    @Test
    fun fileWhitelist_siblingsAndNamePrefixLookalikesDenied() {
        sandbox(allow("/home/test/example")).assertDenied(
            "/home/test/example2",
            "/home/test/exampl",
            "/home/test/other",
            "/home/other/example"
        )
    }

    @Test
    fun fileWhitelist_matchingIsCaseSensitive() {
        sandbox(allow("/home/test/example")).assertDenied(
            "/home/test/Example", "/HOME/test/example"
        )
    }

    @Test
    fun fileWhitelist_emptyPathDenied() {
        sandbox(allow("/home/test/example")).assertDenied("")
    }

    // ---------------------------------------------------------------
    // Directory whitelist (directory + everything below)
    // ---------------------------------------------------------------

    @Test
    fun dirWhitelist_directoryItselfAllowed() {
        sandbox(allow("/home/test/")).assertAllowed("/home/test/")
    }

    @Test
    fun dirWhitelist_directAndDeeplyNestedChildrenAllowed() {
        sandbox(allow("/home/test/")).assertAllowed(
            "/home/test/file",
            "/home/test/sub/",
            "/home/test/sub/file",
            "/home/test/a/b/c/d/e/file"
        )
    }

    @Test
    fun dirWhitelist_siblingsAndNamePrefixLookalikesDenied() {
        sandbox(allow("/home/test/")).assertDenied(
            "/home/test2/file",
            "/home/tes/file",
            "/home/other/file",
            "/homework/test/file"
        )
    }

    @Test
    fun dirWhitelist_directoryPathWithoutTrailingSlashTreatedAsFileAndAllowed() {
        sandbox(allow("/home/test/")).assertAllowed("/home/test")
    }

    // ---------------------------------------------------------------
    // Root rules
    // ---------------------------------------------------------------

    @Test
    fun root_whitelistAllowsEveryAbsolutePath() {
        sandbox(allow("/")).assertAllowed(
            "/", "/home", "/home/", "/home/test/example", "/home/test/example/", "/a/b/c/d"
        )
    }

    @Test
    fun root_blocklistDeniesEveryPath() {
        sandbox(block("/")).assertDenied(
            "/", "/home", "/home/", "/home/test/example", "/home/test/example/", ""
        )
    }

    @Test
    fun root_blocklistAfterWhitelistDeniesEverything() {
        sandbox(allow("/"), block("/")).assertDenied("/", "/home/test")
    }

    @Test
    fun root_blockIsPrioritized() {
        sandbox(block("/"), allow("/")).assertDenied("/", "/home/test")
    }

    // ---------------------------------------------------------------
    // Deepest rule wins
    // ---------------------------------------------------------------

    @Test
    fun deepest_blocklistedSubdirectoryInsideWhitelistedDirectory() {
        val rules = sandbox(allow("/home/"), block("/home/test/example/"))

        rules.assertAllowed("/home/", "/home/test/", "/home/test/other", "/home/other/file", "/")
        rules.assertDenied("/home/test/example/", "/home/test/example/test", "")
    }

    @Test
    fun deepest_directoryBlocklistCoverSameNameWithoutSlash() {
        sandbox(allow("/home/"), block("/home/test/example/"))
            .assertDenied("/home/test/example")
    }

    @Test
    fun deepest_whitelistNestedInsideBlocklistReallowsSubtree() {
        val rules = sandbox(allow("/"), block("/home/"), allow("/home/test/"))

        rules.assertAllowed("/", "/etc/passwd", "/home/test/", "/home/test/file")
        rules.assertDenied("/home/", "/home/other", "/home/other/file")
    }

    @Test
    fun deepest_threeLevelsOfAlternation() {
        val rules = sandbox(allow("/a/"), block("/a/b/"), allow("/a/b/c/"), block("/a/b/c/d/"))

        rules.assertAllowed("/a/x", "/a/b/c/x", "/a/b/c/y/z")
        rules.assertDenied("/a/b/x", "/a/b/", "/a/b/c/d/", "/a/b/c/d/x", "/x")
    }

    @Test
    fun deepest_fileWhitelistInsideBlocklistedDirectoryOnlyAllowsThatFile() {
        val rules = sandbox(allow("/"), block("/secret/"), allow("/secret/public.txt"))

        rules.assertAllowed("/secret/public.txt", "/other", "/secret/public.txt/child")
        rules.assertDenied("/secret/", "/secret/private.txt")
    }

    @Test
    fun deepest_fileBlocklistInsideWhitelistedDirectoryOnlyBlocksThatFile() {
        val rules = sandbox(allow("/data/"), block("/data/secret.txt"))

        rules.assertAllowed("/data/", "/data/a.txt", "/data/sub/secret.txt")
        rules.assertDenied("/data/secret.txt")
    }

    @Test
    fun deepest_ruleOrderDoesNotMatterAtDifferentDepths() {
        val a = sandbox(allow("/home/"), block("/home/test/"))
        val b = sandbox(block("/home/test/"), allow("/home/"))

        listOf("/home/x", "/home/test/", "/home/test/x", "/").forEach { path ->
            assertEquals(
                "Rule order changed the result for '$path'",
                StorageSandbox.isPathAllowed(path, a),
                StorageSandbox.isPathAllowed(path, b)
            )
        }
    }

    // ---------------------------------------------------------------
    // Multiple independent rules
    // ---------------------------------------------------------------

    @Test
    fun multiple_siblingWhitelistsAllHonored() {
        val rules = sandbox(allow("/a/"), allow("/b/"), allow("/c/file"))

        rules.assertAllowed("/a/x", "/b/y/z", "/c/file")
        rules.assertDenied("/c/other", "/d/x")
    }

    @Test
    fun multiple_whitelistingSamePathTwiceIsIdempotent() {
        val rules = sandbox(allow("/a/"), allow("/a/"))

        rules.assertAllowed("/a/", "/a/x")
        rules.assertDenied("/b")
    }

    @Test
    fun multiple_blocklistingNeverWhitelistedPathChangesNothing() {
        val rules = sandbox(allow("/a/"), block("/z/"))

        rules.assertAllowed("/a/x")
        rules.assertDenied("/z/", "/z/x", "/")
    }

    @Test
    fun multiple_orderNotImportant() {
        sandbox(allow("/a/"), block("/a/")).assertDenied("/a/", "/a/x")
        sandbox(block("/a/"), allow("/a/")).assertDenied("/a/", "/a/x")
    }

    // ---------------------------------------------------------------
    // Malformed / unusual input
    // ---------------------------------------------------------------

    @Test
    fun malformed_relativePathsDenied() {
        sandbox(allow("/home/test/"))
            .assertDenied("home/test/file", "./home/test/file", "test/file")
    }

    @Test
    fun malformed_whitespaceOnlyAndPaddedPathsDenied() {
        sandbox(allow("/home/test/"))
            .assertDenied(" ", " /home/test/file", "/home/test /file")
    }

    @Test
    fun malformed_repeatedSlashesDoNotEscapeRuleTree() {
        sandbox(allow("/home/test/")).assertDenied("//home//other//file")
    }

    @Test
    fun malformed_unicodeAndSpecialCharactersMatchedLiterally() {
        val rules = sandbox(allow("/home/tëst/"), allow("/data/we ird&name"))

        rules.assertAllowed("/home/tëst/ファイル", "/data/we ird&name")
        rules.assertDenied("/home/test/file", "/data/we ird&nam")
    }

    // ---------------------------------------------------------------
    // Path traversal (security-critical)
    // ---------------------------------------------------------------

    @Test
    fun traversal_dotDotCannotEscapeWhitelistedDirectory() {
        sandbox(allow("/home/test/")).assertDenied(
            "/home/test/../other/file",
            "/home/test/../../etc/passwd",
            "/home/test/sub/../../../etc/passwd"
        )
    }

    @Test
    fun traversal_dotDotCannotReenterBlocklistedDirectory() {
        val rules = sandbox(allow("/home/"), block("/home/secret/"))
        rules.assertDenied(
            "/home/test/../secret/file",
            "/home/./secret/file"
        )
    }

    @Test
    fun traversal_dotDotInsideAllowedAreaDoesNotThrow() {
        StorageSandbox.isPathAllowed("/home/test/a/../b", sandbox(allow("/home/test/")))
    }

    @Test
    fun traversal_singleDotSegmentAllowsFile() {
        sandbox(allow("/home/test/example")).assertAllowed("/home/test/example/.")
    }
}