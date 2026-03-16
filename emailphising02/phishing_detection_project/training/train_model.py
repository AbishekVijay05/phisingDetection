import argparse
import subprocess
import sys


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", choices=["naive_bayes", "roberta"], required=True)
    p.add_argument("--data_csv", required=True)
    p.add_argument("--output_dir", required=True)

    # RoBERTa args
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch_size", type=int, default=16)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--max_length", type=int, default=512)

    # NB args
    p.add_argument("--max_features", type=int, default=50000)
    p.add_argument("--min_df", type=int, default=2)
    p.add_argument("--ngram_min", type=int, default=1)
    p.add_argument("--ngram_max", type=int, default=2)
    args = p.parse_args()

    if args.model == "naive_bayes":
        cmd = [
            sys.executable,
            "training/train_naive_bayes.py",
            "--data_csv",
            args.data_csv,
            "--output_dir",
            args.output_dir,
            "--max_features",
            str(args.max_features),
            "--min_df",
            str(args.min_df),
            "--ngram_min",
            str(args.ngram_min),
            "--ngram_max",
            str(args.ngram_max),
        ]
    else:
        cmd = [
            sys.executable,
            "training/train_roberta.py",
            "--data_csv",
            args.data_csv,
            "--output_dir",
            args.output_dir,
            "--epochs",
            str(args.epochs),
            "--batch_size",
            str(args.batch_size),
            "--lr",
            str(args.lr),
            "--max_length",
            str(args.max_length),
        ]

    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    main()

