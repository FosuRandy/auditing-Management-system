from app import app
import firebase_routes  # This imports all the Firebase-based routes

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
