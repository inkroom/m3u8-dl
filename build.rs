fn main() {
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=vfw32"); // 修复 capCreateCaptureWindowA
        println!("cargo:rustc-link-lib=mfplat"); // 修复 IID_IMFMediaEventGenerator
        println!("cargo:rustc-link-lib=ncrypt"); // 修复 NCryptOpenStorageProvider
        println!("cargo:rustc-link-lib=mfuuid"); // 修复 IID_IMFTransform
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=oleaut32");
        println!("cargo:rustc-link-lib=shlwapi");
        println!("cargo:rustc-link-lib=strmiids");
        println!("cargo:rustc-link-lib=uuid");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=secur32");
    }
}
