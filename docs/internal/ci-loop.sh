#!/usr/bin/env bash
set -u
BR=$(git branch --show-current)
WF=build-dashboard-plugin.yml
latest() { gh run list --workflow=$WF --branch="$BR" --limit=1 --json databaseId -q '.[0].databaseId'; }
git push origin "$BR" || exit 1
before=$(latest)
gh workflow run $WF --ref "$BR"
for i in $(seq 1 20); do
  sleep 5
  id=$(latest)
  [ "$id" != "$before" ] && break
done
echo "Watching run $id"
if gh run watch "$id" --exit-status; then
  echo "BUILD PASSED"; exit 0
fi
gh run view "$id" --log-failed > ~/failed-log.txt
grep -n -E "ERROR in|Module not found|error TS|Killed|ENOENT|EACCES|heap" ~/failed-log.txt | head -40
echo "Full log: ~/failed-log.txt"
