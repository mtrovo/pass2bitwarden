# pass2bitwarden
Tool to help one migrate from pass (or gopass) to bitwarden.

It generates a CSV file based on all local logins, passwords, custom key value pairs and TOTP secrets.
This CSV file can later be used to import the local data into a bitwarden account going to 
`Vault > Settings > Import Data` and selecting the source format as `bitwarden (csv)`.

## Installing
```
go get github.com/mtrovo/pass2bitwarden
pass2bitwarden --help
```