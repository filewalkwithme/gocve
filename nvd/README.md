# Build the CVE database

The following commands will create a sqlite3 database containing the most recent
version of the NVD database. The output file will be located at `db/cve.sqlite3`

```
docker build -t go-cve-dictionary .
docker run -v $(pwd)/db:/db go-cve-dictionary
```
