# QUICKSTART — Run the Lab in 3 Commands

Open PowerShell inside the project folder, then:

---

## 1. Build
```powershell
docker compose build
```

## 2. Start
```powershell
docker compose up -d
```

## 3. Run the Scanner
```powershell
# Vulnerable server → expect: VULNERABLE
python scripts/detect_cve.py --url http://127.0.0.1:8080

# Patched server → expect: PATCHED / SECURE
python scripts/detect_cve.py --url http://127.0.0.1:8081
```

---

That's it. Lab is running.

---

## Want more detail?

```powershell
# Test path traversal (file read)
python scripts/validate_traversal.py --url http://127.0.0.1:8080

# Test remote code execution via CGI
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id"
```

## Stop when done
```powershell
docker compose down
```
