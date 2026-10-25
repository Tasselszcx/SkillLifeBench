Runtime decision track

14 models x 89 tasks x 2 conditions = 2,492 Default records.
hosted/: 12 models, 2,136 records; qwen/: 356 Default plus 178 Check records.
runtime-case-verdicts.jsonl and runtime-leaderboard.csv are the final merged results.

Run python -m skilllifebench verify --full --output /tmp/skilllifebench-check
from the repository root. See docs/reproduction.md.
The sealed subpackages retain their original protocol and provenance metadata.

Private host paths are represented by stable /slb aliases. publication-bindings.json
records original and published digests for transformed merged result files.
Each evidence package separately seals its public archives and records source
identities; scoring data and task outcomes are unchanged.
