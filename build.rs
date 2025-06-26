fn main() {
    // This is the standard, officially recommended build script for any PyO3 project.
    // It automatically detects the correct Python version and sets all necessary
    // compiler and linker flags. Do not add manual `println!` statements here.
    pyo3_build_config::use_pyo3_cfgs();
}