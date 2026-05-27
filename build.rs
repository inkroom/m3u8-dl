fn main() {
  #[cfg(target_os = "windows")]
  {
    println!("cargo:rustc-link-lib=strmiids");
    println!("cargo:rustc-link-lib=mfuuid");
    println!("cargo:rustc-link-lib=ole32");
    println!("cargo:rustc-link-lib=oleaut32");
  }
}