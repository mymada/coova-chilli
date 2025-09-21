use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// A database of locally defined users for authentication.
#[derive(Debug, Clone, Default)]
pub struct LocalUsers {
    users: Arc<RwLock<HashMap<String, String>>>,
}

impl LocalUsers {
    /// Creates a new, empty local user database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads users from a file at the given path.
    ///
    /// The file should be in the format `username:password` per line.
    /// Lines starting with # are treated as comments and ignored.
    pub fn load<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        info!("Loading local users from {}", path.display());

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut users = self.users.write().unwrap();
        users.clear();

        for line in reader.lines() {
            let line = line?;
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            if let Some((username, password)) = line.split_once(':') {
                users.insert(username.to_string(), password.to_string());
            } else {
                warn!("Malformed line in local users file: {}", line);
            }
        }

        info!("Loaded {} local users.", users.len());
        Ok(())
    }

    /// Checks if a user exists and verifies their password.
    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        let users = self.users.read().unwrap();
        users
            .get(username)
            .map_or(false, |stored_password| stored_password == password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_and_verify_users() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# This is a comment").unwrap();
        writeln!(temp_file, "testuser:testpass").unwrap();
        writeln!(temp_file, "another:anotherpass").unwrap();
        writeln!(temp_file, "malformedline").unwrap();
        writeln!(temp_file, "").unwrap();

        let db = LocalUsers::new();
        db.load(temp_file.path()).unwrap();

        assert!(db.verify_password("testuser", "testpass"));
        assert!(db.verify_password("another", "anotherpass"));
        assert!(!db.verify_password("testuser", "wrongpass"));
        assert!(!db.verify_password("nonexistent", "somepass"));

        // Check that malformed lines are ignored and don't affect valid users
        let users = db.users.read().unwrap();
        assert_eq!(users.len(), 2);
    }
}
