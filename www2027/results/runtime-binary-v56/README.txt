Runtime decision track

14 models x 89 tasks x 2 conditions = 2,492 Default records.
hosted/: 12 models, 2,136 records; qwen/: 356 Default plus 178 Check records.
runtime-case-verdicts.jsonl and runtime-leaderboard.csv are the final merged results.

Run python scripts/verify_release.py --full --output /tmp/skilllifebench-check
from the repository root. See docs/reproduction.md.
The sealed subpackages retain their original protocol and provenance metadata.
