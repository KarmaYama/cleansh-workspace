// cleansh/tests/platform_test.rs
use cleansh::utils::platform::eof_key_combo;

#[test]
fn test_eof_key_combo_is_correct() {
    if cfg!(windows) {
        assert_eq!(eof_key_combo(), "Ctrl+Z");
    } else {
        assert_eq!(eof_key_combo(), "Ctrl+D");
    }
}