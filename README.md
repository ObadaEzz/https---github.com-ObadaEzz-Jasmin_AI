
# Flask Authentication App

This is a simple Flask-based web application that provides user registration, login, and JWT-protected profile access functionality. It uses SQLite for data storage and Flask-JWT-Extended for token-based authentication.

## Features

- User registration with hashed passwords
- User login with JWT token generation
- Token-protected profile route
- SQLite database with SQLAlchemy ORM
- HTML templates for forms and basic navigation

## Requirements

- Python 3.7+
- Flask
- Flask-JWT-Extended
- Flask-SQLAlchemy
- Werkzeug

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-repo/flask-auth-app.git
   cd flask-auth-app
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app**
   ```bash
   python app.py
   ```

5. Access the app at: [http://localhost:5000](http://localhost:5000)

## Usage

- **Register:** Go to `/register`, fill out the form to create an account.
- **Login:** Go to `/login`, enter your credentials to receive a JWT and access the profile page.
- **Profile:** Access `/profile` with the JWT token in the `Authorization` header as `Bearer <token>`.

## API Endpoints

| Method   | Endpoint    | Description                      |
|----------|-------------|----------------------------------|
| GET      | `/`         | Home page                        |
| GET/POST | `/register` | User registration               |
| GET/POST | `/login`    | User login and token generation |
| GET      | `/profile`  | Protected route (requires JWT)  |

## License

This project is licensed under the MIT License.
