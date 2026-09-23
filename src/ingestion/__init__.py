"""CampaignScope Data Ingestion & Cleaning Module."""

from src.ingestion.cleaner import DataCleaner, CleanedEvent
from src.ingestion.spark_pipeline import run_cleaning_pipeline

__all__ = ["DataCleaner", "CleanedEvent", "run_cleaning_pipeline"]
