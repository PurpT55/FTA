# droidtriage

Offline analysis of Android evidence collected by **DroidCollector** or `tools/adb_collect.sh`.
Python ≥ 3.9, standard library only. Full documentation: [`../docs/GUIDE.md`](../docs/GUIDE.md) §5.

```bash
pip install -e .                       # or run in place: python3 -m droidtriage …
droidtriage iocs update                # stalkerware + MVT spyware feeds
droidtriage analyze evidence.zip       # -> evidence_report/report.html
droidtriage --help                     # all commands
python3 -m unittest discover -s tests -t .
```

Architecture: `cli.py` → `pipeline.py` runs every analyser registered with `@analyzer` (`registry.py`)
in order, each reading the `Evidence` and writing `Finding`s / timeline events into the `Context`
(`model.py`); `report.py` renders JSON/CSV/HTML. Extending: see `.claude/skills/add-detection-rule`.
