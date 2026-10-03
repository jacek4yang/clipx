$ErrorActionPreference = 'Stop'
git config --local user.name jacek4yang
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git config --local user.email jacek4yang@outlook.com
exit $LASTEXITCODE
