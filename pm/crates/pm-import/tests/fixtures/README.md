# Nginx Proxy Manager Database Import Test Fixtures

This directory contains test fixtures for the Nginx Proxy Manager database import functionality.

## Offline Limitations

The NPM database import functionality requires the `rusqlite` dependency to read SQLite databases.
This dependency is not available in the offline environment and cannot be fetched without
network access. The implementation is provided here as a documentation and planning artifact.

## Expected Structure

In a real environment, this would contain:
- `npm.db` - Sample Nginx Proxy Manager SQLite database file
- `npm.sql` - Database schema dump for reference

## Implementation Notes

The actual implementation will:
1. Use `rusqlite` to connect to SQLite database files
2. Query the `hosts` table to extract host entries
3. Map each host row to the appropriate import function (import_proxy, import_redirection, import_dead)
4. Handle the conversion from NPM's database format to caddy-rs native format

## Testing

The offline tests verify that the import infrastructure is correctly structured and that
the offline blocker is properly documented, but do not actually read real databases.