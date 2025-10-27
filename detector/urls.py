# ============================================================================
# FILE: detector/urls.py
# ============================================================================
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('analyze/', views.analyze, name='analyze'),
    path('results/<int:scan_id>/', views.results, name='results'),
    path('history/', views.history, name='history'),
    path('quick-scan/', views.quick_scan, name='quick_scan'),
]