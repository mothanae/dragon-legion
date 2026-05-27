# Add project specific ProGuard rules here.

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the native library
-keep class com.celllink.NativeBridge { *; }

# Keep service classes
-keep class com.celllink.BtsTowerService { *; }
-keep class com.celllink.UeClientService { *; }
