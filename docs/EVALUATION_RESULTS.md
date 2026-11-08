# Synthetic evaluation results

No live evaluation has been run for Phase 1 stabilization. This file is the
generated output target for `backend/scripts/run_eval.py`; the next invocation
will replace this note with timestamped scenario results.

Run from `backend/` with the backend process already running and
`GROQ_API_KEY`, `SOC_AI_INTERNAL_TOKEN`, and optionally `SOC_AI_PORT` exported:

```bash
python scripts/run_eval.py --delay 1 --save-responses eval-responses
```

Evaluation requests use synthetic scenarios. Saved response bodies may still
contain identifying context and should remain local.
