"""Distributed Batch Ingestion and Cleaning Pipeline for CampaignScope.

Implements the PySpark distributed batch processing job with a native
vectorized execution engine fallback for environments without an active JVM.
"""

import os
import sys
import argparse
from typing import Dict, Any, Optional
import pandas as pd

from src.ingestion.cleaner import DataCleaner


def run_spark_pipeline(input_path: str, output_dir: str) -> Dict[str, Any]:
    """Executes the distributed cleaning job using PySpark if available."""
    try:
        from pyspark.sql import SparkSession
        from pyspark.sql.functions import col, udf, when
        from pyspark.sql.types import StringType, IntegerType, StructType, StructField

        print("[*] Initializing PySpark Session for Distributed Ingestion...")
        spark = (
            SparkSession.builder.appName("CampaignScope-DataIngestion")
            .config("spark.sql.shuffle.partitions", "8")
            .getOrCreate()
        )

        schema = StructType([
            StructField("timestamp", StringType(), True),
            StructField("ip_address", StringType(), True),
            StructField("username", StringType(), True),
            StructField("endpoint", StringType(), True),
            StructField("user_agent", StringType(), True),
            StructField("status_code", IntegerType(), True),
            StructField("country", StringType(), True),
            StructField("response_time", IntegerType(), True),
            StructField("device_id", StringType(), True),
        ])

        print(f"[*] Reading raw telemetry from {input_path} into Spark DataFrame...")
        df = spark.read.option("header", "true").schema(schema).csv(input_path)

        # Register UDFs for distributed normalization
        cleaner = DataCleaner()
        ua_udf = udf(cleaner.normalize_user_agent, StringType())
        ep_udf = udf(cleaner.normalize_endpoint, StringType())
        user_udf = udf(cleaner.normalize_username, StringType())

        # Filtering and standardization transformations
        clean_df = (
            df.filter(col("ip_address").isNotNull() & col("username").isNotNull() & col("timestamp").isNotNull())
            .withColumn("user_agent_raw", col("user_agent"))
            .withColumn("user_agent", ua_udf(col("user_agent")))
            .withColumn("endpoint", ep_udf(col("endpoint")))
            .withColumn("username", user_udf(col("username")))
            .dropDuplicates(["timestamp", "ip_address", "username", "endpoint"])
        )

        os.makedirs(output_dir, exist_ok=True)
        parquet_out = os.path.join(output_dir, "cleaned_authentication_logs.parquet")
        print(f"[*] Writing distributed partitions to Parquet: {parquet_out}")
        clean_df.write.mode("overwrite").parquet(parquet_out)

        total_rows = clean_df.count()
        spark.stop()
        return {"engine": "PySpark", "final_rows": total_rows, "output_path": parquet_out}

    except Exception as exc:
        print(f"[!] PySpark unavailable or JVM not configured ({exc}).")
        print("[*] Switching to Native Vectorized Engine (Pandas/Arrow)...")
        return run_native_pipeline(input_path, output_dir)


def run_native_pipeline(input_path: str, output_dir: str) -> Dict[str, Any]:
    """Executes the high-speed vectorized data cleaning pipeline locally."""
    print(f"[*] Reading raw telemetry from {input_path}...")
    df_raw = pd.read_csv(input_path)

    cleaner = DataCleaner()
    df_clean, stats = cleaner.clean_dataframe(df_raw)

    os.makedirs(output_dir, exist_ok=True)
    csv_out = os.path.join(output_dir, "cleaned_authentication_logs.csv")
    parquet_out = os.path.join(output_dir, "cleaned_authentication_logs.parquet")

    print(f"[*] Exporting cleaned dataset to CSV: {csv_out}")
    df_clean.to_csv(csv_out, index=False)

    print(f"[*] Exporting cleaned dataset to Parquet: {parquet_out}")
    df_clean.to_parquet(parquet_out, index=False)

    stats["engine"] = "Vectorized-Native"
    stats["csv_output"] = csv_out
    stats["parquet_output"] = parquet_out
    return stats


def run_cleaning_pipeline(input_path: str, output_dir: str, prefer_spark: bool = True) -> Dict[str, Any]:
    """Primary entry point for Phase 2 data cleaning pipeline."""
    if prefer_spark:
        return run_spark_pipeline(input_path, output_dir)
    return run_native_pipeline(input_path, output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CampaignScope Data Ingestion & Cleaning Pipeline")
    parser.add_argument("--input", type=str, default="dataset/raw/authentication_logs.csv", help="Input raw CSV path")
    parser.add_argument("--output-dir", type=str, default="dataset/cleaned", help="Output directory for cleaned data")
    parser.add_argument("--native-only", action="store_true", help="Force native engine without attempting PySpark")
    args = parser.parse_args()

    results = run_cleaning_pipeline(args.input, args.output_dir, prefer_spark=not args.native_only)
    print("\n[+] Data Cleaning Pipeline Completed Successfully!")
    print("--------------------------------------------------")
    for k, v in results.items():
        print(f"  {k:30}: {v}")
    print("--------------------------------------------------")
