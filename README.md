
# VeriQuantum (minimal) — Render & Heroku ready

Minimal Flask app with homepage, login page, and a /health endpoint.

## Local run
```
pip install -r requirements.txt
python app_main.py
```

## Deploy to Render
1. Push this repo to GitHub as `veriquantum`.
2. On https://render.com → New → Web Service
3. Select your repo.
4. Build Command:
   ```
   pip install -r requirements.txt
   ```
5. Start Command:
   ```
   gunicorn app_main:app --timeout 120 --workers 2 --threads 2 --bind 0.0.0.0:$PORT
   ```
6. After deploy, test health: `https://YOUR-SERVICE.onrender.com/health`

## Deploy to Heroku
```
heroku create veriquantum-app
heroku stack:set heroku-22
git push heroku main
heroku open
# health: https://veriquantum-app.herokuapp.com/health
```

## Routes
- `/` homepage (title only)
- `/login` basic login form (placeholder)
- `/health` returns `{"status":"ok"}`
