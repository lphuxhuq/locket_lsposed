# --- libxposed module rules (from libxposed/api README) ---------------------
# The annotation artifact is compileOnly and absent at runtime.
-dontwarn io.github.libxposed.annotation.**

# The framework reads entry class names from this file; R8 must rewrite it when
# the entry classes get obfuscated, otherwise the module silently never loads.
-adaptresourcefilecontents META-INF/xposed/java_init.list

# Entry classes are instantiated reflectively by the framework via a no-arg ctor.
-keep,allowoptimization,allowobfuscation public class * extends io.github.libxposed.api.XposedModule {
    public <init>();
}
