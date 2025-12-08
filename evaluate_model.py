#!/usr/bin/env python3
"""
Model Evaluation Script for Ransomware Detection

This script loads the trained ML model and evaluates it against predefined test cases.
Results are logged to logs/test_results.log with timestamps and detailed metrics.
"""

import logging
import sys
import os
from datetime import datetime
from pathlib import Path

# Add the current directory to Python path to import detector modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector.ml_model import load_model_artifacts, predict_ransomware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/test_results.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Predefined test cases (same as in views.py)
TEST_CASES = {
    'benign': {
        'name': 'Benign File',
        'expected': 'Benign',
        'data': {
            'registry_read': 2, 'registry_write': 1, 'registry_delete': 0,
            'registry_total': 3, 'network_threats': 0, 'network_dns': 1,
            'network_http': 1, 'network_connections': 2, 'processes_malicious': 0,
            'processes_suspicious': 0, 'processes_monitored': 3, 'total_procsses': 3,
            'files_malicious': 0, 'files_suspicious': 0, 'files_text': 15,
            'files_unknown': 1, 'dlls_calls': 20, 'apis': 50,
        }
    },
    'suspicious': {
        'name': 'Suspicious File',
        'expected': 'Malware',
        'data': {
            'registry_read': 8, 'registry_write': 4, 'registry_delete': 1,
            'registry_total': 13, 'network_threats': 1, 'network_dns': 3,
            'network_http': 2, 'network_connections': 5, 'processes_malicious': 0,
            'processes_suspicious': 2, 'processes_monitored': 6, 'total_procsses': 8,
            'files_malicious': 1, 'files_suspicious': 2, 'files_text': 8,
            'files_unknown': 3, 'dlls_calls': 60, 'apis': 120,
        }
    },
    'malware': {
        'name': 'Malware File',
        'expected': 'Malware',
        'data': {
            'registry_read': 25, 'registry_write': 15, 'registry_delete': 8,
            'registry_total': 48, 'network_threats': 8, 'network_dns': 12,
            'network_http': 10, 'network_connections': 18, 'processes_malicious': 5,
            'processes_suspicious': 7, 'processes_monitored': 20, 'total_procsses': 32,
            'files_malicious': 10, 'files_suspicious': 8, 'files_text': 3,
            'files_unknown': 15, 'dlls_calls': 250, 'apis': 500,
        }
    }
}

def evaluate_model():
    """Load model and run evaluation on test cases."""
    logger.info("Starting model evaluation...")

    try:
        # Load model artifacts
        logger.info("Loading model artifacts...")
        model, scaler, features, encoders, target_enc = load_model_artifacts()
        logger.info("Model artifacts loaded successfully")

        # Run evaluation on each test case
        results = {}
        total_tests = len(TEST_CASES)
        correct_predictions = 0

        for test_key, test_case in TEST_CASES.items():
            logger.info(f"Testing {test_case['name']}...")

            # Run prediction
            result = predict_ransomware(
                test_case['data'],
                model=model,
                scaler=scaler,
                feature_names=features,
                label_encoders=encoders,
                target_encoder=target_enc
            )

            # Check if prediction matches expected
            is_correct = result['prediction'] == test_case['expected']
            if is_correct:
                correct_predictions += 1

            # Log detailed results
            logger.info(f"Test Case: {test_case['name']}")
            logger.info(f"Expected: {test_case['expected']}")
            logger.info(f"Predicted: {result['prediction']}")
            logger.info(f"Confidence: {result['confidence']:.2f}%")
            logger.info(f"Malware Probability: {result['malware_probability']:.2f}%")
            logger.info(f"Risk Level: {result['risk_level']}")
            logger.info(f"Recommendation: {result['recommendation']}")
            logger.info(f"Correct: {is_correct}")
            logger.info("-" * 50)

            results[test_key] = {
                'test_name': test_case['name'],
                'expected': test_case['expected'],
                'predicted': result['prediction'],
                'confidence': result['confidence'],
                'malware_probability': result['malware_probability'],
                'risk_level': result['risk_level'],
                'recommendation': result['recommendation'],
                'correct': is_correct
            }

        # Calculate and log overall accuracy
        accuracy = (correct_predictions / total_tests) * 100
        logger.info(f"Evaluation Complete!")
        logger.info(f"Total Tests: {total_tests}")
        logger.info(f"Correct Predictions: {correct_predictions}")
        logger.info(f"Accuracy: {accuracy:.2f}%")

        return results, accuracy

    except Exception as e:
        logger.error(f"Error during model evaluation: {str(e)}")
        raise

def main():
    """Main function to run the evaluation."""
    start_time = datetime.now()
    logger.info("=" * 60)
    logger.info("MODEL EVALUATION STARTED")
    logger.info(f"Start Time: {start_time}")
    logger.info("=" * 60)

    try:
        results, accuracy = evaluate_model()

        end_time = datetime.now()
        duration = end_time - start_time

        logger.info("=" * 60)
        logger.info("MODEL EVALUATION COMPLETED")
        logger.info(f"End Time: {end_time}")
        logger.info(f"Duration: {duration}")
        logger.info(f"Final Accuracy: {accuracy:.2f}%")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"Evaluation failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()