use crate::q_keygen::derive_key;

#[test]
fn test_user_salt() {
    let (key1, salt1) = derive_key("password", Some("saltphrase")).unwrap();
    let (key2, salt2) = derive_key("password", Some("saltphrase")).unwrap();
    assert_eq!(key1, key2);
    assert_eq!(salt1, salt2);
}

#[test]
fn test_random_salt() {
    let (key1, salt1) = derive_key("password", None).unwrap();
    let (key2, salt2) = derive_key("password", None).unwrap();
    assert_ne!(key1, key2);
    assert_ne!(salt1, salt2);
}

#[test]
fn test_invalid_salt() {
    let (key1, salt1) = derive_key("password", Some("saltphrase1")).unwrap();
    let (key2, salt2) = derive_key("password", Some("saltphrase2")).unwrap();
    assert_ne!(key1, key2);
    assert_ne!(salt1, salt2);
}