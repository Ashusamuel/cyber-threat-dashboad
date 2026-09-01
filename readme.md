# Cyber Threat Intelligence (CTI) Dashboard
An interactive, real-time Cyber Threat Intelligence visualization platform designed to monitor global attack vectors, telemetry data, and threat actor metrics. Built for high-visibility monitoring with live filtering, country-level drill-downs, and dynamic geo-mapping.
---

## Live Links
- **Frontend Application (Netlify):** [https://your-cti-dashboard.netlify.app](https://your-cti-dashboard.netlify.app)
- **Backend API (Render):** [https://cti-dashboard-api.onrender.com](https://cti-dashboard-api.onrender.com)
---
## Tech Stack & Architecture
### Frontend
- **Core Languages:** HTML5, CSS3, JavaScript (ES6+)
- **Visualization & Maps:** Chart.js, 3D Globe Visualizer / Leaflet.js
- **Deployment:** Netlify

### Backend
- **Framework:** Python (Flask / FastAPI)
- **Networking & CORS:** `flask-cors`
- **Data Integrations:** Open threat feeds & REST API endpoints
- **Deployment:** Render

---
## Local Setup & Installation
Follow these steps to clone and run the project locally on your machine.
### Prerequisites
- Python 3.9+
- Git
### 1. Clone the Repository
``bash
git clone [https://github.com/your-username/cti-dashboard.git](https://github.com/your-username/cti-dashboard.git)
cd cti-dashboard
 
------
## Backend Config
# Navigate to backend directory
cd backend
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
# Install required dependencies
pip install -r requirements.txt
# Start the local development server
python app.py

# Optional: Serve locally using Python HTTP server
cd ../frontend
python3 -m http.server 3000