#!/bin/bash
# migrate_passwords.sh - Migrate plaintext passwords to bcrypt hashes
# Usage: ./migrate_passwords.sh /path/to/localusers

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <localusers_file>"
    echo "Example: $0 /etc/coovachilli/localusers"
    exit 1
fi

USERS_FILE="$1"
BACKUP_FILE="${USERS_FILE}.backup.$(date +%Y%m%d-%H%M%S)"
TEMP_FILE="${USERS_FILE}.new"

# Check if file exists
if [ ! -f "$USERS_FILE" ]; then
    echo "Error: File $USERS_FILE not found"
    exit 1
fi

# Check if coovachilli binary exists
if ! command -v coovachilli &> /dev/null; then
    echo "Error: coovachilli binary not found in PATH"
    echo "Please ensure CoovaChilli-Go is built and in your PATH"
    exit 1
fi

# Create backup
echo "Creating backup: $BACKUP_FILE"
cp "$USERS_FILE" "$BACKUP_FILE"

echo "Migrating passwords to bcrypt..."

# Process each line
while IFS=: read -r username password; do
    # Skip empty lines and comments
    if [ -z "$username" ] || [[ "$username" =~ ^# ]]; then
        continue
    fi

    # Check if already bcrypt (starts with $2)
    if [[ "$password" =~ ^\$2 ]]; then
        echo "  $username: Already using bcrypt, skipping"
        echo "$username:$password" >> "$TEMP_FILE"
    else
        echo "  $username: Migrating plaintext password to bcrypt..."

        # Generate bcrypt hash using Go
        HASH=$(cat <<EOF | go run -
package main
import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
    "os"
)
func main() {
    password := os.Args[1]
    hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    fmt.Print(string(hash))
}
EOF
"$password"
)

        if [ $? -ne 0 ]; then
            echo "Error generating hash for $username"
            exit 1
        fi

        echo "$username:$HASH" >> "$TEMP_FILE"
    fi
done < "$USERS_FILE"

# Replace original file
echo "Replacing original file..."
mv "$TEMP_FILE" "$USERS_FILE"
chmod 600 "$USERS_FILE"

echo ""
echo "Migration completed successfully!"
echo "Backup saved to: $BACKUP_FILE"
echo "Updated file: $USERS_FILE"
echo ""
echo "IMPORTANT: Please verify authentication still works before deleting the backup."
