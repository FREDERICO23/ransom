# ============================================================================
# FILE: detector/models.py
# ============================================================================

from django.db import models
from django.utils import timezone

class ScanResult(models.Model):
    RISK_LEVELS = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
    ]
    
    PREDICTIONS = [
        ('Benign', 'Benign'),
        ('Malware', 'Malware'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now)
    file_name = models.CharField(max_length=255, blank=True, null=True)
    prediction = models.CharField(max_length=20, choices=PREDICTIONS)
    confidence = models.FloatField()
    malware_probability = models.FloatField()
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS)
    recommendation = models.CharField(max_length=50)
    
    # Feature values
    registry_read = models.IntegerField(default=0)
    registry_write = models.IntegerField(default=0)
    registry_delete = models.IntegerField(default=0)
    network_threats = models.IntegerField(default=0)
    processes_malicious = models.IntegerField(default=0)
    files_malicious = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.prediction} - {self.risk_level} ({self.timestamp.strftime('%Y-%m-%d %H:%M')})"