# ============================================================================
# FILE: detector/admin.py
# ============================================================================
from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'prediction', 'risk_level', 'confidence', 'file_name']
    list_filter = ['prediction', 'risk_level', 'timestamp']
    search_fields = ['file_name']
    readonly_fields = ['timestamp']