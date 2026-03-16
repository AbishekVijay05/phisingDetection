import argparse
import os
import sys
from typing import Any, Dict, List

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ensemble.hybrid_model import HybridEnsemble
from inference.eml_parser import load_eml_file
from model.naive_bayes_model import load_naive_bayes, predict_proba_phishing, top_terms
from model.roberta_model import attention_token_scores, load_roberta, predict_proba_phishing_roberta


def _predict_all(texts: List[str], nb_dir: str, roberta_dir: str, ensemble: HybridEnsemble) -> Dict[str, Any]:
    nb = load_naive_bayes(nb_dir)
    ro = load_roberta(roberta_dir)

    nb_p = predict_proba_phishing(nb, texts)
    ro_p = predict_proba_phishing_roberta(ro, texts)
    hy_p = ensemble.combine(ro_p, nb_p)

    return {"nb": nb, "ro": ro, "nb_p": nb_p, "ro_p": ro_p, "hy_p": hy_p}


def _lime_explain(text: str, nb_dir: str, roberta_dir: str, ensemble: HybridEnsemble, num_features: int = 10) -> Dict[str, Any]:
    from lime.lime_text import LimeTextExplainer  # lazy import

    nb = load_naive_bayes(nb_dir)
    ro = load_roberta(roberta_dir)

    class_names = ["Safe", "Phishing"]
    explainer = LimeTextExplainer(class_names=class_names)

    def predict_proba_for_lime(text_list: List[str]) -> np.ndarray:
        nb_p = predict_proba_phishing(nb, text_list)
        ro_p = predict_proba_phishing_roberta(ro, text_list)
        hy_p = ensemble.combine(ro_p, nb_p)
        # Return 2-column probabilities [p_safe, p_phish]
        return np.vstack([1.0 - hy_p, hy_p]).T

    exp = explainer.explain_instance(text, predict_proba_for_lime, num_features=num_features)
    return {
        "lime_hybrid_top_features": exp.as_list(label=1),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--nb_dir", required=True)
    p.add_argument("--roberta_dir", required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Raw email text")
    g.add_argument("--eml_path", help="Path to .eml file to scan")
    g.add_argument("--eml_dir", help="Directory containing .eml files (batch scan)")
    g.add_argument("--input_csv", help="Path to CSV file containing emails to scan")
    p.add_argument("--csv_text_col", default="text", help="Text column name if using --input_csv")
    p.add_argument("--ensemble_mode", choices=["soft", "weighted"], default="weighted")
    p.add_argument("--weights", nargs=2, type=float, default=[0.7, 0.3])
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--explain", action="store_true")
    p.add_argument("--out_csv", default=None, help="When using --eml_dir or --input_csv, write a CSV report to this path")
    args = p.parse_args()

    if args.eml_dir:
        eml_files = []
        for root, _, files in os.walk(args.eml_dir):
            for f in files:
                if f.lower().endswith(".eml"):
                    eml_files.append(os.path.join(root, f))
        eml_files.sort()
        if not eml_files:
            raise SystemExit(f"No .eml files found under: {args.eml_dir}")
        texts = [load_eml_file(p) for p in eml_files]
    elif args.input_csv:
        import pandas as pd
        df = pd.read_csv(args.input_csv)
        if args.csv_text_col not in df.columns:
            raise SystemExit(f"Column '{args.csv_text_col}' not found in {args.input_csv}")
        # Drop missing
        df = df.dropna(subset=[args.csv_text_col])
        texts = df[args.csv_text_col].astype(str).tolist()
    else:
        text = args.text if args.text is not None else load_eml_file(args.eml_path)
        texts = [text]

    ensemble = HybridEnsemble(
        mode=args.ensemble_mode, roberta_weight=float(args.weights[0]), nb_weight=float(args.weights[1])
    )
    res = _predict_all(texts, args.nb_dir, args.roberta_dir, ensemble)

    if args.eml_dir or args.input_csv:
        import pandas as pd

        hy = res["hy_p"]
        pred = (hy >= args.threshold).astype(int)
        
        if args.eml_dir:
            out_dict = {"path": eml_files}
        else:
            out_dict = {"original_index": df.index, "text_snippet": [t[:100] for t in texts]}
            
        out_dict.update({
            "roberta_proba": res["ro_p"],
            "naive_bayes_proba": res["nb_p"],
            "final_proba": res["hy_p"],
            "prediction": HybridEnsemble.classify_batch_binary(res["hy_p"]),
        })
        out = pd.DataFrame(out_dict)
        if args.out_csv:
            out.to_csv(args.out_csv, index=False)
            print(f"Wrote report: {args.out_csv}")
        else:
            print(out.to_string(index=False))
        return

    ro_p = float(res["ro_p"][0])
    nb_p = float(res["nb_p"][0])
    hy_p = float(res["hy_p"][0])
    pred = HybridEnsemble.classify_binary(hy_p)

    print(f"RoBERTa Probability: {ro_p:.4f}")
    print(f"Naive Bayes Probability: {nb_p:.4f}")
    print(f"Final Probability ({args.ensemble_mode}): {hy_p:.4f}")
    print(f"Prediction: {pred}")

    if args.explain:
        print("\nExplainability:")

        # NB global indicative terms
        nb_terms = top_terms(res["nb"], top_k=12)
        print("- Naive Bayes indicative terms (global):")
        print("  phishing:", ", ".join([t for t, _ in nb_terms.get("phishing", [])[:10]]))
        print("  legitimate:", ", ".join([t for t, _ in nb_terms.get("legitimate", [])[:10]]))

        # RoBERTa attention token importance
        try:
            att = attention_token_scores(res["ro"], texts[0], top_k=12)
            print("- RoBERTa attention top tokens:", ", ".join([t for t, _ in att]))
        except Exception as e:
            print(f"- RoBERTa attention unavailable: {e}")

        # LIME (hybrid)
        try:
            lime = _lime_explain(texts[0], args.nb_dir, args.roberta_dir, ensemble, num_features=10)
            print("- LIME (hybrid) important features:")
            for feat, weight in lime["lime_hybrid_top_features"]:
                print(f"  {feat}: {weight:.4f}")
        except Exception as e:
            print(f"- LIME unavailable: {e}")


if __name__ == "__main__":
    main()

