# Usage report

This file describes the run that wrote the repository-root `output.csv`.

## Run

| Item | Value |
| --- | --- |
| Command | `python3 code/main.py` |
| Date | 2026-11-18 |
| Requests | 518 (`dataset/deletion_requests.csv`) |
| Output rows | 518 |
| Runtime model calls | 0 |

The auditor is a deterministic Python program. It does not call an LLM, embedding API, or other model while scoring a case. OCR, when used, is local Tesseract on the evidence screenshots.

## Tokens and cost

| Provider | Model | Calls | Input tokens | Output tokens | Cost |
| --- | --- | ---: | ---: | ---: | ---: |
| none | none (deterministic auditor) | 0 | 0 | 0 | $0.00 |
| **Overall** |  | **0** | **0** | **0** | **$0.00** |

| Aggregate | Value |
| --- | ---: |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

No API key is read and no paid model endpoint is contacted.

## Development note

The program was written with the Cursor coding agent using the runtime model `grok-4.7-high-fast`. That assistance is not part of the scoring run above. Token counts and a dollar cost for the coding session were not metered by the auditor, so they are not invented here. Re-running `python3 code/main.py` reproduces `output.csv` without a model.
