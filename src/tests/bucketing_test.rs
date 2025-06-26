#[cfg(test)]
mod tests {
    use crate::bucketing::bucket_sensitive_data;

    #[test]
    fn test_bucketing() {
        let _ = std::fs::remove_file("/tmp/bucket.txt");
        bucket_sensitive_data("SSN: 123-45-6789", "/tmp/bucket.txt").unwrap();
        let contents = std::fs::read_to_string("/tmp/bucket.txt").unwrap();
        assert!(contents.contains("123-45-6789"));
    }
}