# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

-keep class com.additionsecurity.MobileAwareness {
    public *;
}

-keep class com.additionsecurity.MobileAwareness.OperationException {
    public *;
}

-keep class com.additionsecurity.MobileAwareness.LicenseException {
    public *;
}

-keep class com.additionsecurity.MobileAwareness.SecurityException {
    public *;
}

-keep class com.additionsecurity.MobileAwareness.LibraryException {
    public *;
}

-keep class com.additionsecurity.MobileAwareness.ConfigurationFileException {
    public *;
}

-keep class com.additionsecurity.MobileAwareness.ArmOnX86Exception {
    public *;
}

-keep class com.additionsecurity.IMobileAwarenessCallback {
    public *;
}

-keepclasseswithmembers class com.additionsecurity.MobileAwareness$B {
    *;
}
