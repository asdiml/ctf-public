## Dumping the Library Search Priority for Python on Windows Powershell

The following command where the double quotes need to be escaped has to be used

```powershell
python -c 'import sys; print(\"\n\".join(sys.path))'
```