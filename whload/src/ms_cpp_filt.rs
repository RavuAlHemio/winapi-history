use msvc_demangler::{demangle, DemangleFlags};


pub fn demangle_cpp_name(input: &str) -> Result<String, String> {
    let flags = DemangleFlags::llvm();
    demangle(input, flags)
        .map_err(|e| e.to_string())
}
