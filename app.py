import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
import mysql.connector
from mysql.connector import pooling
import requests
from cachetools import TTLCache, cached
from datetime import datetime, timedelta, UTC
from decimal import Decimal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TICKETMASTER_API_KEY = 'your ticket master api'

CATEGORIES = {
    'Music': 'music',
    'Theatre': 'theatre',
    'Sports': 'sports',
    'Arts & Family': 'arts & theatre'
}

db_pool = pooling.MySQLConnectionPool( #it is default db settings,u can change passwd and db name if u want
    pool_name="event_pool",
    pool_size=10,
    host="127.0.0.1",
    user="root",
    password="",
    database="event_manager"
)
logger.info("MySQL connection pool created.")

def get_db():
    return db_pool.get_connection()

def get_weather_codes():
    return {
        0: "Açık hava", 1: "Çoğunlukla açık", 2: "Parçalı bulutlu", 3: "Kapalı",
        45: "Sis", 48: "Kırağı sis", 51: "Hafif çise", 53: "Orta çise",
        55: "Yoğun çise", 56: "Hafif donan çise", 57: "Yoğun donan çise",
        61: "Hafif yağmur", 63: "Orta yağmur", 65: "Şiddetli yağmur",
        66: "Hafif donan yağmur", 67: "Şiddetli donan yağmur",
        71: "Hafif kar", 73: "Orta kar", 75: "Yoğun kar",
        77: "Kar taneleri", 80: "Hafif yağmur sağanakları", 81: "Orta yağmur sağanakları",
        82: "Şiddetli yağmur sağanakları", 85: "Hafif kar sağanakları",
        86: "Yoğun kar sağanakları", 95: "Fırtına",
        96: "Hafif dolu ile fırtına", 99: "Yoğun dolu ile fırtına"
    }

def can_event_proceed(weather_code):
    bad_weather_codes = [65, 67, 75, 82, 95, 96, 99]
    return weather_code not in bad_weather_codes

environment_cache = TTLCache(maxsize=100, ttl=600)
@cached(environment_cache)
def get_weather_info(location: str, event_date: str) -> dict | None:
    try:
        logger.info(f"Fetching weather for location: {location}, date: {event_date}")
        event_dt = datetime.strptime(event_date, '%Y-%m-%d %H:%M:%S')
        today = datetime.now(UTC)
        forecast_limit = today + timedelta(days=16)
        if event_dt.date() > forecast_limit.date():
            logger.warning(f"Event date {event_dt.date()} is out of forecast range")
            return {
                'temperature': '-°C',
                'description': 'Tahmin Yok',
                'can_proceed': True,
                'weather_code': None
            }
        geo = requests.get(
            'https://geocoding-api.open-meteo.com/v1/search',
            params={'name': location, 'count': 1}
        )
        geo.raise_for_status()
        results = geo.json().get('results') or []
        if not results:
            logger.warning(f"No geocoding results for {location}")
            return None
        lat = results[0]['latitude']
        lon = results[0]['longitude']
        date_str = event_dt.strftime('%Y-%m-%d')
        resp = requests.get(
            'https://api.open-meteo.com/v1/forecast',
            params={
                'latitude': lat,
                'longitude': lon,
                'daily': 'weathercode,temperature_2m_max',
                'timezone': 'Europe/Istanbul',
                'start_date': date_str,
                'end_date': date_str
            }
        )
        resp.raise_for_status()
        daily = resp.json().get('daily', {})
        weather_code = daily.get('weathercode', [None])[0]
        temp = daily.get('temperature_2m_max', [None])[0]
        return {
            'temperature': f"{temp}°C" if temp is not None else '-°C',
            'description': get_weather_codes().get(weather_code, 'Bilinmiyor'),
            'can_proceed': can_event_proceed(weather_code) if weather_code is not None else True,
            'weather_code': weather_code
        }
    except Exception as e:
        logger.error(f"Weather API error for {location}: {str(e)}")
        return None

ticketmaster_cache = TTLCache(maxsize=1, ttl=3600)
@cached(ticketmaster_cache)
def fetch_and_store_ticketmaster_events(api_key: str):
    all_events = []
    seen_events = set()
    today = datetime.now(UTC)
    end_date = today + timedelta(days=16)
    target_count = 20
    size_per_category = 5
    country_codes = ['TR']
    with get_db() as conn:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id FROM ticketmaster_events WHERE is_valid = TRUE")
            existing_ids = {row['id'] for row in cursor.fetchall()}
            logger.info(f"Existing valid Ticketmaster event IDs: {existing_ids}")
            for country_code in country_codes:
                if len(all_events) >= target_count:
                    break
                for category_name, category_query in CATEGORIES.items():
                    if len(all_events) >= target_count:
                        break
                    for attempt in range(2):
                        try:
                            url = 'https://app.ticketmaster.com/discovery/v2/events.json'
                            params = {
                                'apikey': api_key,
                                'countryCode': country_code,
                                'size': size_per_category,
                                'classificationName': category_query,
                                'startDateTime': today.strftime('%Y-%m-%dT%H:%M:%SZ'),
                                'endDateTime': end_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
                                'sort': 'date,asc'
                            }
                            logger.info(f"Attempt {attempt + 1}: Fetching Ticketmaster events for {category_name} in {country_code} with params: {params}")
                            response = requests.get(url, params=params, timeout=10)
                            response.raise_for_status()
                            data = response.json()
                            events_fetched = data.get('_embedded', {}).get('events', [])
                            logger.info(f"Fetched {len(events_fetched)} {category_name} events from Ticketmaster in {country_code}")
                            for ev in events_fetched:
                                event_id = ev['id']
                                if event_id in seen_events or len(all_events) >= target_count:
                                    continue
                                seen_events.add(event_id)
                                venue = ev.get('_embedded', {}).get('venues', [{}])[0]
                                city = venue.get('city', {}).get('name', '')
                                state = venue.get('state', {}).get('name', '')
                                location = f"{city}, {state}".strip(', ')
                                date_str = ev.get('dates', {}).get('start', {}).get('dateTime')
                                if not date_str:
                                    continue
                                date_obj = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC) + timedelta(hours=3)
                                price = ev.get('priceRanges', [{}])[0].get('min', 50.0)
                                classifications = ev.get('classifications', [{}])
                                if classifications:
                                    primary_genre = classifications[0].get('segment', {}).get('name')
                                    category_name = next((k for k, v in CATEGORIES.items() if v.lower() in primary_genre.lower()), category_name)
                                image = ev.get('images', [{}])[0].get('url', '')
                                event_data = {
                                    'id': event_id,
                                    'title': ev['name'],
                                    'description': ev.get('info', '') or 'No description',
                                    'date': date_obj,
                                    'category': category_name,
                                    'total_tickets': 1000,
                                    'available_tickets': 1000,
                                    'ticket_price': float(price),
                                    'location': location or 'Bilinmiyor',
                                    'is_outdoor': False,
                                    'external_url': ev.get('url', ''),
                                    'is_valid': True,
                                    'image': image
                                }
                                all_events.append(event_data)
                                if event_id in existing_ids:
                                    cursor.execute(
                                        "UPDATE ticketmaster_events SET title=%s, description=%s, date=%s, category=%s, "
                                        "total_tickets=%s, available_tickets=%s, ticket_price=%s, location=%s, is_outdoor=%s, "
                                        "external_url=%s, is_valid=%s, last_checked=CURRENT_TIMESTAMP, image=%s WHERE id=%s",
                                        (event_data['title'], event_data['description'], event_data['date'], event_data['category'],
                                        event_data['total_tickets'], event_data['available_tickets'], event_data['ticket_price'],
                                        event_data['location'], event_data['is_outdoor'], event_data['external_url'],
                                        event_data['is_valid'], event_data['image'], event_id)
                                    )
                                    existing_ids.remove(event_id)
                                    logger.info(f"Updated existing Ticketmaster event: {event_id}")
                                else:
                                    cursor.execute(
                                        "INSERT INTO ticketmaster_events (id, title, description, date, category, total_tickets, "
                                        "available_tickets, ticket_price, location, is_outdoor, external_url, is_valid, image) "
                                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                                        (event_id, event_data['title'], event_data['description'], event_data['date'],
                                        event_data['category'], event_data['total_tickets'], event_data['available_tickets'],
                                        event_data['ticket_price'], event_data['location'], event_data['is_outdoor'],
                                        event_data['external_url'], event_data['is_valid'], event_data['image'])
                                    )
                                    logger.info(f"Inserted new Ticketmaster event: {event_id}")
                                conn.commit()
                                if len(all_events) >= target_count:
                                    break
                            break
                        except Exception as e:
                            logger.error(f"Attempt {attempt + 1} failed for {category_name} in {country_code}: {e}")
                            if attempt == 1:
                                logger.warning(f"Skipping {category_name} in {country_code} after 2 failed attempts")
                            continue
            for event_id in existing_ids:
                cursor.execute(
                    "UPDATE ticketmaster_events SET is_valid = FALSE, last_checked = CURRENT_TIMESTAMP WHERE id = %s",
                    (event_id,)
                )
                conn.commit()
                logger.info(f"Marked event {event_id} as invalid (no longer exists)")
            logger.info(f"Stored {len(all_events)} Ticketmaster events")
    return all_events

def fetch_events(available_only=False, category=None, within_days=None):
    with get_db() as conn:
        with conn.cursor(dictionary=True) as cur:
            query = """
                SELECT id, title, description, date, category, total_tickets, available_tickets, ticket_price, location, is_outdoor 
                FROM events 
                WHERE date >= CONVERT_TZ(NOW(), 'SYSTEM', '+03:00')
            """
            params = []
            conditions = []
            if available_only:
                conditions.append("available_tickets >= 0")
            if category:
                conditions.append("category = %s")
                params.append(category)
            if within_days:
                end_date = datetime.now(UTC) + timedelta(days=within_days)
                conditions.append("date <= %s")
                params.append(end_date)
            if conditions:
                query += " AND " + " AND ".join(conditions)
            query += " ORDER BY date ASC"
            logger.info(f"Local events query: {query} with params: {params}")
            cur.execute(query, params)
            local_events = cur.fetchall()
            logger.info(f"Fetched {len(local_events)} local events")
            for e in local_events:
                e['is_external'] = False
                date_str = e['date'].strftime('%Y-%m-%d %H:%M:%S')
                e['weather'] = get_weather_info(e['location'], date_str) or {
                    'temperature': '-°C',
                    'description': 'Hava durumu bilgisi yok',
                    'can_proceed': True,
                    'weather_code': None
                }

            query = """
                SELECT id, title, description, date, category, total_tickets, available_tickets, ticket_price, location, is_outdoor, external_url, image 
                FROM ticketmaster_events 
                WHERE is_valid = TRUE AND date >= CONVERT_TZ(NOW(), 'SYSTEM', '+03:00')
            """
            params = []
            conditions = []
            if within_days:
                end_date = datetime.now(UTC) + timedelta(days=within_days)
                conditions.append("date <= %s")
                params.append(end_date)
            if conditions:
                query += " AND " + " AND ".join(conditions)
            query += " ORDER BY date ASC"
            logger.info(f"Ticketmaster events query: {query} with params: {params}")
            cur.execute(query, params)
            tm_events = cur.fetchall()
            logger.info(f"Fetched {len(tm_events)} Ticketmaster events")
            for e in tm_events:
                e['is_external'] = True
                date_str = e['date'].strftime('%Y-%m-%d %H:%M:%S')
                e['weather'] = get_weather_info(e['location'], date_str) or {
                    'temperature': '-°C',
                    'description': 'Hava durumu bilgisi yok',
                    'can_proceed': True,
                    'weather_code': None
                }

            all_events = local_events + tm_events
            logger.info(f"Total events before deduplication: {len(all_events)}")
            seen = set()
            unique_events = []
            for e in all_events:
                key = (e['title'].lower(), e['date'].strftime('%Y-%m-%d %H:%M:%S'), e['location'].lower())
                if key not in seen:
                    seen.add(key)
                    unique_events.append(e)
                else:
                    logger.info(f"Removed duplicate event: {e['title']} at {e['date']} in {e['location']}")
            logger.info(f"Returning {len(unique_events)} unique events (local: {len(local_events)}, Ticketmaster: {len(tm_events)})")
            return unique_events[:20]

def get_recommended_events(user_id):
    with get_db() as conn:
        with conn.cursor(dictionary=True) as cur:
            cur.execute("SELECT interests FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            interests = user['interests'].split(',') if user and user['interests'] else list(CATEGORIES.keys())
            logger.info(f"User {user_id} interests: {interests}")
            events = fetch_events(available_only=True, within_days=16)
            recommended = [e for e in events if e['category'].lower() in [i.lower() for i in interests]]
            logger.info(f"Recommended events: {[e['title'] for e in recommended]}")
            recommended.sort(key=lambda x: x['date'])
            return recommended

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'change_this_secret_key') #yep my secret key is 'change_this_secret_key' 
    Talisman(app, content_security_policy=None)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
    )

    ticketmaster_cache.clear()
    environment_cache.clear()
    logger.info("Caches cleared on startup")

    @app.route('/')
    def home():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM ticketmaster_events WHERE is_valid = TRUE AND date >= NOW() AND date <= %s", 
                        (datetime.now(UTC) + timedelta(days=16),))
                tm_count = cur.fetchone()[0]
                if tm_count < 7:
                    logger.info("Triggering Ticketmaster fetch due to insufficient events")
                    fetch_and_store_ticketmaster_events(TICKETMASTER_API_KEY)
        events = fetch_events(available_only=True, within_days=16)
        events.sort(key=lambda x: x['date'])
        with get_db() as conn:
            with conn.cursor(dictionary=True) as c:
                c.execute('SELECT * FROM announcements ORDER BY date DESC')
                anns = c.fetchall()
        recommended = get_recommended_events(session['user_id'])
        logger.info(f"Home page rendering {len(events)} events and {len(recommended)} recommended events")
        return render_template('index.html', events=events, announcements=anns, recommended=recommended)

    @app.route('/events')
    def events():
        events = fetch_events(available_only=True)
        events.sort(key=lambda x: x['date'])
        logger.info(f"Events page rendering {len(events)} events")
        return render_template('events.html', events=events)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            u = request.form['username']
            p = request.form['password']
            with get_db() as conn:
                with conn.cursor(dictionary=True) as cur:
                    cur.execute('SELECT * FROM users WHERE username=%s', (u,))
                    user = cur.fetchone()
                    if not user:
                        return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
                    try:
                        if check_password_hash(user['password'], p):
                            if not user['is_approved']:
                                return render_template('login.html', error='Hesabınız henüz onaylanmadı.')
                            session['user_id'] = user['id']
                            session['is_admin'] = user['is_admin']
                            if user['must_change_password']:
                                return redirect(url_for('change_password'))
                            return redirect(url_for('home'))
                        else:
                            return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
                    except ValueError as e:
                        logger.error(f"Invalid password hash for user {u}: {e}")
                        return render_template('login.html', error='Geçersiz şifre formatı. Yönetici ile iletişime geçin.')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            u = request.form['username']
            p = request.form['password']
            cp = request.form['confirm_password']
            interests = ','.join(request.form.getlist('interests'))
            if p != cp:
                return render_template('register.html', error='Şifreler eşleşmiyor')
            hp = generate_password_hash(p)
            with get_db() as conn:
                with conn.cursor() as cur:
                    try:
                        cur.execute(
                            'INSERT INTO users (username, password, is_approved, interests) VALUES (%s, %s, 0, %s)',
                            (u, hp, interests)
                        )
                        conn.commit()
                        return render_template('login.html', message='Kayıt başarılı. Yönetici onayı bekleniyor.')
                    except mysql.connector.IntegrityError:
                        return render_template('register.html', error='Bu kullanıcı adı zaten kullanılıyor')
        return render_template('register.html')

    @app.route('/change_password', methods=['GET', 'POST'])
    def change_password():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if request.method == 'POST':
            np = request.form['new_password']
            cp = request.form['confirm_password']
            if np != cp:
                return render_template('change_password.html', error='Şifreler eşleşmiyor')
            hp = generate_password_hash(np)
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute('UPDATE users SET password=%s, must_change_password=0 WHERE id=%s', (hp, session['user_id']))
                    conn.commit()
            return redirect(url_for('home'))
        return render_template('change_password.html')

    @app.route('/profile', methods=['GET', 'POST'])
    def profile():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('SELECT interests FROM users WHERE id=%s', (session['user_id'],))
                user = cur.fetchone()
                current_interests = user['interests'].split(',') if user['interests'] else []
                if request.method == 'POST':
                    interests = ','.join(request.form.getlist('interests'))
                    cur.execute('UPDATE users SET interests=%s WHERE id=%s', (interests, session['user_id']))
                    conn.commit()
                    flash('İlgi alanlarınız güncellendi.', 'success')
                    return redirect(url_for('profile'))
                return render_template('profile.html', current_interests=current_interests)

    @app.route('/api/events')
    def api_events():
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        category = request.args.get('category')
        events = fetch_events(available_only=True, category=category, within_days=16)
        def serialize_event(e):
            return {
                'id': e['id'],
                'title': e['title'],
                'description': e.get('description', ''),
                'date': e['date'].isoformat() if hasattr(e['date'], 'isoformat') else e['date'],
                'category': e.get('category', ''),
                'location': e.get('location', ''),
                'is_outdoor': e.get('is_outdoor', False),
                'is_external': e.get('is_external', False),
                'available_tickets': e.get('available_tickets', 0),
                'ticket_price': float(e.get('ticket_price', 0)),
                'weather': e.get('weather', {}),
                'image': e.get('image', '')
            }
        serialized = [serialize_event(ev) for ev in events]
        return jsonify(serialized)

    @app.route('/api/update_interests', methods=['POST'])
    def update_interests():
        if 'user_id' not in session:
            return jsonify({'error': 'Yetkisiz erişim'}), 401
        data = request.get_json()
        interests = data.get('interests', [])
        interests_str = ','.join(interests)
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE users SET interests=%s WHERE id=%s', (interests_str, session['user_id']))
                conn.commit()
        recommended = get_recommended_events(session['user_id'])
        return jsonify({'message': 'İlgi alanları güncellendi', 'recommended': [e['title'] for e in recommended]})

    @app.route('/admin/approve_users')
    def approve_users():
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('SELECT * FROM users WHERE is_approved=0')
                users = cur.fetchall()
                return render_template('approve_users.html', users=users)

    @app.route('/admin/approve_user/<int:user_id>')
    def approve_user(user_id):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE users SET is_approved=1 WHERE id=%s', (user_id,))
                conn.commit()
        return redirect(url_for('approve_users'))

    @app.route('/admin/assign_admin', methods=['GET', 'POST'])
    def assign_admin():
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('SELECT * FROM users WHERE is_approved=1 AND is_admin=0')
                users = cur.fetchall()
                if request.method == 'POST':
                    user_id = request.form.get('user_id')
                    cur.execute('UPDATE users SET is_admin=1 WHERE id=%s', (user_id,))
                    conn.commit()
                    flash('Kullanıcı admin olarak atandı.', 'success')
                    return redirect(url_for('assign_admin'))
                return render_template('assign_admin.html', users=users)

    @app.route('/my_tickets')
    def my_tickets():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('''
                    SELECT t.*, e.title, e.date, e.location
                    FROM tickets t
                    JOIN events e ON t.event_id = e.id
                    WHERE t.user_id=%s
                ''', (session['user_id'],))
                local_tickets = cur.fetchall()
                cur.execute('''
                    SELECT t.*, te.title, te.date, te.location
                    FROM tickets t
                    JOIN ticketmaster_events te ON t.event_id = te.id
                    WHERE t.user_id=%s
                ''', (session['user_id'],))
                tm_tickets = cur.fetchall()
                tickets = local_tickets + tm_tickets
                return render_template('my_tickets.html', tickets=tickets)

    @app.route('/buy_ticket/<event_id>', methods=['GET', 'POST'])
    def buy_ticket(event_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                if event_id.startswith('tm_'):
                    tm_id = event_id[3:]
                    cur.execute('SELECT * FROM ticketmaster_events WHERE id=%s AND is_valid=TRUE', (tm_id,))
                else:
                    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
                event = cur.fetchone()
                if not event:
                    return "Etkinlik bulunamadı", 404
                event['is_external'] = event_id.startswith('tm_')
                weather = get_weather_info(event['location'], event['date'].strftime('%Y-%m-%d %H:%M:%S'))
                event['weather'] = weather or {'temperature': '-°C', 'description': 'Hava durumu bilgisi yok', 'can_proceed': True, 'weather_code': None}
                weather_warning = event['is_outdoor'] and event['weather'] and not event['weather']['can_proceed']
                multipliers = {'standard': 1.0, 'vip': 1.5, 'student': 0.8}
                prices = {
                    'standard': round(float(event['ticket_price']) * multipliers['standard'], 2),
                    'vip': round(float(event['ticket_price']) * multipliers['vip'], 2),
                    'student': round(float(event['ticket_price']) * multipliers['student'], 2)
                }
                error = None
                if request.method == 'POST':
                    try:
                        ttype = request.form['ticket_type']
                        qty = int(request.form['quantity'])
                        if qty <= 0:
                            error = "Lütfen geçerli bir bilet adedi giriniz."
                        elif not event['is_external'] and qty > event['available_tickets']:
                            error = "Yeterli bilet yok."
                        else:
                            price = prices[ttype]
                            total = price * qty
                            db_event_id = tm_id if event['is_external'] else event_id
                            cur.execute(
                                'INSERT INTO cart (user_id, event_id, ticket_type, quantity) VALUES (%s, %s, %s, %s)',
                                (session['user_id'], db_event_id, ttype, qty)
                            )
                            conn.commit()
                            flash('Bilet sepete eklendi.', 'success')
                            return redirect(url_for('cart'))
                    except (ValueError, KeyError):
                        error = "Geçersiz form verisi."
                return render_template('buy_ticket.html', 
                                    event=event, 
                                    error=error, 
                                    weather_warning=weather_warning,
                                    prices=prices)

    @app.route('/cart', methods=['GET'])
    def cart():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('''
                    SELECT c.*, e.title, e.date, e.location, e.ticket_price, NULL as external_url
                    FROM cart c JOIN events e ON c.event_id=e.id
                    WHERE c.user_id=%s
                ''', (session['user_id'],))
                cart_items = cur.fetchall()
                for item in cart_items:
                    multipliers = {'standard': 1.0, 'vip': 1.5, 'student': 0.8}
                    price = float(item['ticket_price']) * multipliers.get(item['ticket_type'], 1.0)
                    item['price'] = price
                    item['total'] = price * item['quantity']
                    item['is_external'] = False
                cur.execute('''
                    SELECT c.*, te.title, te.date, te.location, te.ticket_price, te.external_url
                    FROM cart c JOIN ticketmaster_events te ON c.event_id=te.id
                    WHERE c.user_id=%s
                ''', (session['user_id'],))
                tm_cart_items = cur.fetchall()
                for item in tm_cart_items:
                    multipliers = {'standard': 1.0, 'vip': 1.5, 'student': 0.8}
                    price = float(item['ticket_price']) * multipliers.get(item['ticket_type'], 1.0)
                    item['price'] = price
                    item['total'] = price * item['quantity']
                    item['is_external'] = True
                all_cart_items = cart_items + tm_cart_items
                seen = set()
                unique_cart_items = []
                for item in all_cart_items:
                    key = (item['event_id'], item['ticket_type'])
                    if key not in seen:
                        seen.add(key)
                        unique_cart_items.append(item)
                total = sum(item['total'] for item in unique_cart_items)
                return render_template('cart.html', cart_items=unique_cart_items, total=total)

    @app.route('/cart/remove/<cart_id>')
    def remove_from_cart(cart_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor() as cur:
                try:
                    cart_id_int = int(cart_id)
                    cur.execute('DELETE FROM cart WHERE id=%s AND user_id=%s', (cart_id_int, session['user_id']))
                    conn.commit()
                except ValueError:
                    flash('Geçersiz sepet öğesi.', 'error')
                    return redirect(url_for('cart'))
        flash('Bilet sepetten kaldırıldı.', 'success')
        return redirect(url_for('cart'))

    @app.route('/cart/purchase', methods=['POST'])
    def purchase_cart():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('''
                    SELECT c.*, e.title, e.ticket_price, e.available_tickets
                    FROM cart c JOIN events e ON c.event_id=e.id
                    WHERE c.user_id=%s
                ''', (session['user_id'],))
                cart_items = cur.fetchall()
                cur.execute('''
                    SELECT c.*, te.title, te.ticket_price, te.available_tickets, te.external_url
                    FROM cart c JOIN ticketmaster_events te ON c.event_id=te.id
                    WHERE c.user_id=%s
                ''', (session['user_id'],))
                tm_cart_items = cur.fetchall()
                if not cart_items and not tm_cart_items:
                    flash('Sepetiniz boş.', 'error')
                    return redirect(url_for('cart'))
                try:
                    for item in cart_items:
                        if item['quantity'] > item['available_tickets']:
                            flash(f"{item['title']} için yeterli bilet yok.", 'error')
                            return redirect(url_for('cart'))
                        multipliers = {'standard': 1.0, 'vip': 1.5, 'student': 0.8}
                        price = float(item['ticket_price']) * multipliers.get(item['ticket_type'], 1.0)
                        total = price * item['quantity']
                        cur.execute('UPDATE events SET available_tickets=%s WHERE id=%s',
                                (item['available_tickets'] - item['quantity'], item['event_id']))
                        cur.execute(
                            'INSERT INTO tickets (user_id, event_id, ticket_type, quantity, total_price) VALUES (%s, %s, %s, %s, %s)',
                            (session['user_id'], item['event_id'], item['ticket_type'], item['quantity'], total)
                        )
                    for item in tm_cart_items:
                        multipliers = {'standard': 1.0, 'vip': 1.5, 'student': 0.8}
                        price = float(item['ticket_price']) * multipliers.get(item['ticket_type'], 1.0)
                        total = price * item['quantity']
                        cur.execute(
                            'INSERT INTO tickets (user_id, event_id, ticket_type, quantity, total_price) VALUES (%s, %s, %s, %s, %s)',
                            (session['user_id'], item['event_id'], item['ticket_type'], item['quantity'], total)
                        )
                    cur.execute('DELETE FROM cart WHERE user_id=%s', (session['user_id'],))
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    logger.error(f"Purchase error: {e}")
                    flash(f'Satın alma hatası: {str(e)}', 'error')
                    return redirect(url_for('cart'))
                flash('Satın alma simülasyonu başarılı.', 'success')
                return redirect(url_for('cart'))

    @app.route('/admin/events', methods=['GET', 'POST'])
    def admin_events():
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                if request.method == 'POST':
                    title = request.form.get('title', '')
                    description = request.form.get('description', '')
                    date = request.form['date']
                    category = request.form['category']
                    total_tickets = int(request.form['total_tickets'])
                    ticket_price = float(request.form['ticket_price'])
                    location = request.form['location']
                    is_outdoor = bool(request.form.get('is_outdoor'))
                    cur.execute('''
                        INSERT INTO events (title, description, date, category, total_tickets, available_tickets, ticket_price, location, is_outdoor)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (title, description, date, category, total_tickets, total_tickets, ticket_price, location, is_outdoor))
                    conn.commit()
                    flash('Etkinlik eklendi.', 'success')
                    return redirect(url_for('admin_events'))
                cur.execute('SELECT * FROM events ORDER BY date')
                events = cur.fetchall()
                cur.execute('SELECT * FROM ticketmaster_events WHERE is_valid=TRUE ORDER BY date')
                tm_events = cur.fetchall()
                return render_template('admin_events.html', events=events, tm_events=tm_events)

    @app.route('/admin/events/edit/<event_id>', methods=['GET', 'POST'])
    def edit_event(event_id):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                if event_id.startswith('tm_'):
                    tm_id = event_id[3:]
                    cur.execute('SELECT * FROM ticketmaster_events WHERE id=%s', (tm_id,))
                else:
                    cur.execute('SELECT * FROM events WHERE id=%s', (event_id,))
                event = cur.fetchone()
                if not event:
                    return "Etkinlik bulunamadı", 404
                if request.method == 'POST':
                    title = request.form.get('title', '')
                    description = request.form.get('description', '')
                    date = request.form['date']
                    category = request.form['category']
                    total_tickets = int(request.form['total_tickets'])
                    ticket_price = float(request.form['ticket_price'])
                    location = request.form['location']
                    is_outdoor = bool(request.form.get('is_outdoor'))
                    if event_id.startswith('tm_'):
                        external_url = request.form.get('external_url', '')
                        image = request.form.get('image', '')
                        cur.execute('''
                            UPDATE ticketmaster_events SET title=%s, description=%s, date=%s, category=%s, total_tickets=%s, ticket_price=%s, location=%s, is_outdoor=%s, external_url=%s, image=%s
                            WHERE id=%s
                        ''', (title, description, date, category, total_tickets, ticket_price, location, is_outdoor, external_url, image, tm_id))
                    else:
                        cur.execute('''
                            UPDATE events SET title=%s, description=%s, date=%s, category=%s, total_tickets=%s, ticket_price=%s, location=%s, is_outdoor=%s
                            WHERE id=%s
                        ''', (title, description, date, category, total_tickets, ticket_price, location, is_outdoor, event_id))
                    conn.commit()
                    flash('Etkinlik güncellendi.', 'success')
                    return redirect(url_for('admin_events'))
                return render_template('edit_event.html', event=event, is_external=event_id.startswith('tm_'))

    @app.route('/admin/events/delete/<event_id>')
    def delete_event(event_id):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor() as cur:
                try:
                    if event_id.startswith('tm_'):
                        tm_id = event_id[3:]
                        cur.execute('UPDATE ticketmaster_events SET is_valid=FALSE WHERE id=%s', (tm_id,))
                    else:
                        cur.execute('DELETE FROM events WHERE id=%s', (event_id,))
                    conn.commit()
                    flash('Etkinlik başarıyla silindi.', 'success')
                except mysql.connector.Error as e:
                    conn.rollback()
                    logger.error(f"Error deleting event {event_id}: {e}")
                    flash('Etkinlik silinirken hata oluştu.', 'error')
        return redirect(url_for('admin_events'))

    @app.route('/admin/announcements', methods=['GET', 'POST'])
    def admin_announcements():
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                if request.method == 'POST':
                    title = request.form.get('title', '')
                    content = request.form.get('content', '')
                    date = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')
                    cur.execute(
                        'INSERT INTO announcements (title, content, date) VALUES (%s, %s, %s)',
                        (title, content, date)
                    )
                    conn.commit()
                    flash('Duyuru eklendi.', 'success')
                    return redirect(url_for('admin_announcements'))
                cur.execute('SELECT * FROM announcements ORDER BY date DESC')
                announcements = cur.fetchall()
                return render_template('admin_announcements.html', announcements=announcements)

    @app.route('/admin/announcements/edit/<int:ann_id>', methods=['GET', 'POST'])
    def edit_announcement(ann_id):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('SELECT * FROM announcements WHERE id=%s', (ann_id,))
                announcement = cur.fetchone()
                if not announcement:
                    return "Duyuru bulunamadı", 404
                if request.method == 'POST':
                    title = request.form.get('title', '')
                    content = request.form.get('content', '')
                    cur.execute(
                        'UPDATE announcements SET title=%s, content=%s WHERE id=%s',
                        (title, content, ann_id)
                    )
                    conn.commit()
                    flash('Duyuru güncellendi.', 'success')
                    return redirect(url_for('admin_announcements'))
                return render_template('edit_announcement.html', announcement=announcement)

    @app.route('/admin/announcements/delete/<int:ann_id>')
    def delete_announcement(ann_id):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM announcements WHERE id=%s', (ann_id,))
                conn.commit()
        flash('Duyuru silindi.', 'success')
        return redirect(url_for('admin_announcements'))

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))
    
    @app.route('/announcements')
    def announcements():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        with get_db() as conn:
            with conn.cursor(dictionary=True) as cur:
                cur.execute('SELECT * FROM announcements ORDER BY date DESC')
                announcements = cur.fetchall()
        return render_template('announcements.html', announcements=announcements)

    @app.route('/admin/check_ticketmaster')
    def trigger_check():
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('login'))
        ticketmaster_cache.clear()
        fetch_and_store_ticketmaster_events(TICKETMASTER_API_KEY)
        flash('Ticketmaster etkinlikleri kontrol edildi ve güncellendi.', 'success')
        return redirect(url_for('admin_events'))

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)