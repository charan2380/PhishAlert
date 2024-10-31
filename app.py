import joblib
import requests
import os
from flask import Flask, render_template, request, make_response, redirect, url_for, flash
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
csrf = CSRFProtect(app)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'phishshield.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Configure Flask-Caching to use on-disk caching
cache_dir = os.path.join(app.root_path, '.cache')
cache = Cache(app, config={'CACHE_TYPE': 'filesystem', 'CACHE_DIR': cache_dir})

# Create a database model for contact submissions
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)

# Loading the trained models
feature_model = joblib.load("models/feature_model.joblib")

# Configure reCAPTCHA keys
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

@app.route('/verify_recaptcha', methods=['GET', 'POST'])
@csrf.exempt
def verify_recaptcha():
    if request.method == 'POST':
        token = request.form.get('g-recaptcha-response')
        if not token:
            return render_template('verification.html', error='Please complete the reCAPTCHA.')
        
        # Verify reCAPTCHA token with Google
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': token
            }
        )

        if response.ok:
            result = response.json()
            if result.get('success'):
                # reCAPTCHA verification successful, set a cookie to indicate verification
                resp = make_response(redirect('/'))
                resp.set_cookie('recaptcha_verified', 'true')
                return resp
            else:
                return render_template('verification.html', error='reCAPTCHA verification failed.')
        else:
            return render_template('verification.html', error='Failed to verify reCAPTCHA. Please try again later.')
    
    return render_template('verification.html', RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

# Defining route for phishing detection
@app.route('/', methods=['GET', 'POST'])
@csrf.exempt
def detect_phishing():
    if request.cookies.get('recaptcha_verified') == 'true':
        if request.method == 'POST':
            url = request.form["url"]  # Getting URL from the form data
            
            # Check if the result is cached
            cached_result = cache.get(url)
            if cached_result:
                return cached_result

            # Check if the URL exists
            try:
                response = requests.get(url, timeout=5)
                # If the request is successful, proceed with prediction
                if response.status_code == 200:
                    # Making prediction using feature-based model
                    feature_pred = feature_model.predict([url])[0]  # Get first prediction result
                    feature_confidence = feature_model.predict_proba([url])[0]  # Get probabilities

                    # Extracting confidence scores for phishing and legitimate classes
                    confidence_phishing_feature = feature_confidence[0] * 100  # Phishing confidence score
                    confidence_legitimate_feature = feature_confidence[1] * 100  # Legitimate confidence score

                    # Defining a threshold for prediction
                    threshold = 50  # Threshold in percentage

                    # Final prediction based on phishing confidence score
                    final_pred = -1 if confidence_phishing_feature > threshold else 1
                    result = "Phishing" if final_pred == -1 else "Legitimate"

                else:
                    # URL does not exist, classify as phishing
                    result = "Phishing"
                    confidence_phishing_feature = 100.0  # Set confidence to 100% phishing
                    confidence_legitimate_feature = 0.0

            except requests.RequestException:
                # If there's any exception (like a timeout), classify as phishing
                result = "Phishing"
                confidence_phishing_feature = 100.0  # Set confidence to 100% phishing
                confidence_legitimate_feature = 0.0

            # Cache the result and the report for 1 hour (3600 seconds)
            cached_render = render_template(
                'index.html',
                url=url,
                result=result,
                confidence_phishing_feature=confidence_phishing_feature,
                confidence_legitimate_feature=confidence_legitimate_feature
            )
            cache.set(url, cached_render, timeout=3600)

            # Returning the cached render
            return cached_render
        else:
            return render_template('index.html')
    else:
        return redirect('/verify_recaptcha')

@app.route('/how_it_works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/contact', methods=['GET'])
def contact():
    return render_template('contact.html')

@app.route('/submit_contact', methods=['POST'])
@csrf.exempt
def submit_contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    # Create a new contact record and add it to the database
    new_contact = Contact(name=name, email=email, message=message)
    db.session.add(new_contact)
    db.session.commit()

    return render_template('contact.html', success=True)

@app.route('/view_contacts', methods=['GET'])
def view_contacts():
    contacts = Contact.query.all()
    return render_template('view_contacts.html', contacts=contacts)

@app.route('/delete_contact/<int:id>', methods=['POST'])
@csrf.exempt
def delete_contact(id):
    contact = Contact.query.get_or_404(id)
    db.session.delete(contact)
    db.session.commit()
    flash('Contact deleted successfully.', 'success')
    return redirect(url_for('view_contacts'))

@app.route('/faq', methods=['GET'])
def faq():
    return render_template('faq.html')

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    # Ensure that the application context is active for db.create_all()
    with app.app_context():
        db.create_all()  # Create the database tables if they don't exist
    app.run(debug=True)
