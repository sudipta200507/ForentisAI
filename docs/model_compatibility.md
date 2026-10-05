# Technical ML Model Compatibility

## Supported artifact formats

| Format | Shape | Produced by | Loader path |
| --- | --- | --- | --- |
| 2 | joblib `TechnicalModelBundle` dataclass (sklearn `Pipeline` + metadata) | `ai/training/train_technical_model.py`, fixture generator | `app/ai/technical_ml/model.py::_validate_v2_bundle` |
| 3 | plain Python `dict` with `model`, `feature_names`, `suspicious_threshold`, provenance | external V1 Colab training pipeline (`ForentisAI_TechnicalML_Dataset_V1`) | `app/ai/technical_ml/model.py::_load_v3_dict` |

The production artifact `ai/models/technical_model.joblib` is **format 3**
(dict, 28 model features, threshold 0.33, dataset
`ForentisAI_TechnicalML_Dataset_V1`, contract `technical-30-eml-v1`).

## scikit-learn version compatibility

- The V1 artifact was **pickled with scikit-learn 1.6.1**.
- The dependency pin is `scikit-learn>=1.6,<1.9` (was `==1.7.2`).
- The loader **does not suppress** sklearn's `InconsistentVersionWarning`:
  the warning is captured during `joblib.load` and recorded verbatim in
  `TechnicalModelV3Bundle.compatibility_note`, and the message is surfaced in
  the `TechnicalMLResult.message` of every prediction.
- Acceptance is **functional, not trusting**: the unpickled estimator must
  pass a deterministic zero-vector `predict_proba` smoke test (correct shape,
  finite values, exactly two classes) before it is accepted. A mismatched
  sklearn version that still passes the smoke test is therefore recorded but
  allowed; a broken estimator is rejected with `incompatible_model`.

## Class-label contract

The V1 artifact stores integer classes `[0, 1]`. The mapping **0 → benign,
1 → suspicious** is verified from the artifact itself: its held-out test
confusion matrix `[[882, 29], [10, 692]]` places the 911-sample benign split
in row 0 (`classes_[0]`) and the 702-sample suspicious split in row 1, and
matches the project-wide class contract (0 = benign, 1 = malicious/
suspicious — same as `FORENTISAI_ID2LABEL` in `app/ai/nlp/model.py`).
String-labelled artifacts (`"benign"`/`"suspicious"`) are accepted directly;
any other class set is rejected as `incompatible_model`.

## Decision rule

Format 3 inference applies the **artifact's stored threshold**
(`suspicious_threshold = 0.33`):

```
predicted = "suspicious" if p_suspicious >= threshold else "benign"
confidence = probability of the predicted class
```

This deliberately differs from the legacy argmax rule (`p_susp >= p_benign`):
within the band `threshold <= p_susp < 0.5` the V1 model flags suspicious by
design (the threshold was selected by validation F1; see
`docs/training_report.json`).

## Feature contract

The model consumes exactly the 28 features recorded in
`bundle.feature_names`, in that order (`text.*` 10 + `header.*` 10 + `url.*`
8). `intelligence.public_ip_count` and `intelligence.non_public_ip_count`
were constant at training time and are excluded. The runtime builds the
input array in the artifact's exact order via
`app.ai.technical_ml.inference.prediction_array`; a name outside the runtime
48-feature contract is a load-time `incompatible_model` error.

## Validation summary (runtime 1.8.0, artifact 1.6.1)

- Load + smoke test: PASS (warning captured, noted on every result).
- Deterministic prediction: PASS (`test_technical_ml_v3.py`).
- SHAP TreeExplainer on the unpickled forest: PASS with canonical labels.
- Orchestrator end-to-end: technical model `available`, fusion combines both
  models (see `tests/ai/test_technical_ml_v3.py::test_real_v3_orchestrator_technical_available`).
