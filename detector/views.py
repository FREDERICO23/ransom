# ============================================================================
# FILE: detector/views.py
# ============================================================================
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from .models import ScanResult
from .ml_model import predict_ransomware, load_model_artifacts
import json

# Load model once at startup
try:
    MODEL, SCALER, FEATURES, ENCODERS, TARGET_ENC = load_model_artifacts()
    MODEL_LOADED = True
except Exception as e:
    MODEL_LOADED = False
    print(f"Error loading model: {e}")

def index(request):
    recent_scans = ScanResult.objects.all()[:10]
    
    # Statistics
    total_scans = ScanResult.objects.count()
    malware_detected = ScanResult.objects.filter(prediction='Malware').count()
    high_risk = ScanResult.objects.filter(risk_level='HIGH').count()
    
    context = {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'malware_detected': malware_detected,
        'high_risk': high_risk,
        'model_loaded': MODEL_LOADED,
    }
    return render(request, 'detector/index.html', context)

def analyze(request):
    if request.method == 'POST':
        try:
            # Get form data
            sample_data = {
                'registry_read': int(request.POST.get('registry_read', 0)),
                'registry_write': int(request.POST.get('registry_write', 0)),
                'registry_delete': int(request.POST.get('registry_delete', 0)),
                'registry_total': int(request.POST.get('registry_total', 0)),
                'network_threats': int(request.POST.get('network_threats', 0)),
                'network_dns': int(request.POST.get('network_dns', 0)),
                'network_http': int(request.POST.get('network_http', 0)),
                'network_connections': int(request.POST.get('network_connections', 0)),
                'processes_malicious': int(request.POST.get('processes_malicious', 0)),
                'processes_suspicious': int(request.POST.get('processes_suspicious', 0)),
                'processes_monitored': int(request.POST.get('processes_monitored', 0)),
                'total_procsses': int(request.POST.get('total_procsses', 0)),
                'files_malicious': int(request.POST.get('files_malicious', 0)),
                'files_suspicious': int(request.POST.get('files_suspicious', 0)),
                'files_text': int(request.POST.get('files_text', 0)),
                'files_unknown': int(request.POST.get('files_unknown', 0)),
                'dlls_calls': int(request.POST.get('dlls_calls', 0)),
                'apis': int(request.POST.get('apis', 0)),
            }
            
            # Predict
            result = predict_ransomware(
                sample_data, 
                model=MODEL, 
                scaler=SCALER, 
                feature_names=FEATURES,
                label_encoders=ENCODERS,
                target_encoder=TARGET_ENC
            )
            
            # Save to database
            scan = ScanResult.objects.create(
                file_name=request.POST.get('file_name', 'Manual Entry'),
                prediction=result['prediction'],
                confidence=result['confidence'],
                malware_probability=result['malware_probability'],
                risk_level=result['risk_level'],
                recommendation=result['recommendation'],
                registry_read=sample_data['registry_read'],
                registry_write=sample_data['registry_write'],
                registry_delete=sample_data['registry_delete'],
                network_threats=sample_data['network_threats'],
                processes_malicious=sample_data['processes_malicious'],
                files_malicious=sample_data['files_malicious'],
            )
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'result': result,
                    'scan_id': scan.id
                })
            
            messages.success(request, f"Analysis complete: {result['prediction']} ({result['risk_level']} Risk)")
            return redirect('results', scan_id=scan.id)
            
        except Exception as e:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': str(e)})
            messages.error(request, f"Error during analysis: {str(e)}")
            return redirect('index')
    
    return render(request, 'detector/analyze.html', {'model_loaded': MODEL_LOADED})

def results(request, scan_id):
    scan = ScanResult.objects.get(id=scan_id)
    context = {'scan': scan}
    return render(request, 'detector/results.html', context)

def history(request):
    scans = ScanResult.objects.all()
    context = {'scans': scans}
    return render(request, 'detector/history.html', context)

def quick_scan(request):
    # Predefined test cases
    test_cases = {
        'benign': {
            'name': 'Benign File',
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
            'data': {
                'registry_read': 15, 'registry_write': 8, 'registry_delete': 3,
                'registry_total': 26, 'network_threats': 3, 'network_dns': 5,
                'network_http': 4, 'network_connections': 8, 'processes_malicious': 2,
                'processes_suspicious': 3, 'processes_monitored': 10, 'total_procsses': 15,
                'files_malicious': 4, 'files_suspicious': 3, 'files_text': 5,
                'files_unknown': 6, 'dlls_calls': 150, 'apis': 300,
            }
        }
    }
    
    test_type = request.GET.get('type', 'benign')
    test_case = test_cases.get(test_type, test_cases['benign'])
    
    try:
        result = predict_ransomware(
            test_case['data'],
            model=MODEL,
            scaler=SCALER,
            feature_names=FEATURES,
            label_encoders=ENCODERS,
            target_encoder=TARGET_ENC
        )
        
        return JsonResponse({
            'success': True,
            'test_name': test_case['name'],
            'result': result
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})