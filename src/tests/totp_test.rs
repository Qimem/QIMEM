#[cfg(test)]
mod tests {
    use crate::totp::{generate_totp_secret, get_totp_code, verify_totp_code};

    #[test]
    fn test_totp() {
        let secret = generate_totp_secret().unwrap();
        let code = get_totp_code(&secret).unwrap();
        assert!(verify_totp_code(&secret, &code).unwrap());
    }
}