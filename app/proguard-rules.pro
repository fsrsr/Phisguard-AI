# ProGuard rules for PhishGuard AI v2.0
# Prevent minification from stripping TFLite native library and classes

# Keep TFLite classes
-keep class org.tensorflow.lite.** { *; }
-keep class org.tensorflow.** { *; }
-keep class com.google.android.gms.** { *; }

# Keep native libraries
-keep class **$Native { *; }
-keep class **$Jni { *; }

# Keep all native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep R class
-keep class **$R { *; }
-keep class **$R$* { *; }

# Keep Firebase classes
-keep class com.google.firebase.** { *; }
-keep class com.google.android.gms.** { *; }

# Keep OkHttp (used by WebsiteReconAgent)
-keep class com.squareup.okhttp3.** { *; }
-keep interface com.squareup.okhttp3.** { *; }

# Keep Gson (used by AI response parsing)
-keep class com.google.gson.** { *; }

# Keep AccessibilityService
-keep class com.phishguard.ai.PhishGuardService { *; }
-keep class com.phishguard.ai.service.SmsNotificationInterceptorService { *; }

# Keep all data classes
-keep class com.phishguard.ai.** { *; }

# Don't obfuscate
-dontobfuscate