# 🛡️ Ransomware Detection App - Complete Setup Guide

## 📋 Overview
A beautiful Django web application for detecting ransomware using trained machine learning model.

## ✨ Features
- 🎨 Modern, responsive dark-themed UI with animations
- 🤖 Real-time ML-powered ransomware detection
- 📊 Interactive dashboard with statistics
- 🔍 Manual feature input for analysis
- ⚡ Quick test scans (Benign/Suspicious/Malware)
- 📜 Complete scan history with database storage
- 🎯 Risk level visualization (Low/Medium/High)
- 📱 Mobile-friendly responsive design
- 🔐 Admin panel for scan management

---

## Setup Instructions


### Install Dependencies
Create and activate virtual env:
```bash
pipenv install
pipenv shell
```

### Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Superuser (Optional)
```bash
python manage.py createsuperuser
```

### Run the Server
```bash
python manage.py runserver
```

### Access the Application
Open your browser and navigate to:
- **Main App**: http://127.0.0.1:8000
- **Admin Panel**: http://127.0.0.1:8000/admin

---


## 🎯 Usage Guide

### Dashboard
- View statistics: Total scans, malware detected, high-risk files
- Quick test buttons to demo the system
- Recent scan history

### Analyze Page
- Enter behavioral features manually
- Use "Load Sample" button for quick testing
- All 18 feature inputs organized by category:
  - Registry Activity (4 fields)
  - Network Activity (4 fields)
  - Process Activity (4 fields)
  - File Activity (4 fields)
  - API Activity (2 fields)

### Results Page
- Visual prediction display with emojis
- Risk level badge (LOW/MEDIUM/HIGH)
- Confidence scores
- Behavioral feature breakdown
- Threat indicators

### History Page
- Complete scan database
- Sortable table view
- Color-coded risk levels
- Quick access to detailed results

---

## 🔧 Troubleshooting

### Model Not Loading
```python
# Check if files exist
import os
from pathlib import Path

model_dir = Path('detector/ml_models')
print(f"Model directory exists: {model_dir.exists()}")
print(f"Files: {list(model_dir.glob('*.pkl'))}")
```

### Database Issues
```bash
# Reset database
rm db.sqlite3
rm -rf detector/migrations
python manage.py makemigrations detector
python manage.py migrate
```

### Static Files Not Loading
```bash
# Collect static files
python manage.py collectstatic
```

---


