use actix_web::{web, App, HttpServer, HttpResponse, HttpRequest, middleware::Logger};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::HashMap;
use chrono::Local;
use uuid::Uuid;
use email_address::EmailAddress;
use rand::Rng;
use log::info;

// Request/Response structures
#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct LogoutResponse {
    status: String,
}

#[derive(Serialize)]
struct TryLuckResponse {
    win: bool,
}

// Token data
#[derive(Clone)]
struct TokenData {
    created_at: chrono::DateTime<Local>,
}

// App state
struct AppState {
    tokens: HashMap<String, TokenData>,
    daily_wins: u32,
    last_reset_day: String,
}

// Helper functions
fn is_valid_email(email: &str) -> bool {
    EmailAddress::parse(email, None).is_ok()
}

fn generate_token() -> String {
    Uuid::new_v4().to_string()
}

fn get_current_day() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

fn reset_daily_wins_if_needed(state: &mut AppState) {
    let current_day = get_current_day();
    if state.last_reset_day != current_day {
        state.daily_wins = 0;
        state.last_reset_day = current_day.clone();
        info!("Daily wins reset for new day");
    }
}

fn calculate_win(state: &AppState) -> bool {
    let mut rng = rand::thread_rng();
    let win_rate = if state.daily_wins >= 30 { 0.4 } else { 0.7 };
    rng.gen::<f64>() < win_rate
}

fn get_token_from_header(req: &HttpRequest) -> Result<String, String> {
    match req.headers().get("Authorization") {
        Some(auth_header) => {
            match auth_header.to_str() {
                Ok(auth_str) => {
                    let parts: Vec<&str> = auth_str.split_whitespace().collect();
                    if parts.len() == 2 && parts[0] == "Bearer" {
                        Ok(parts[1].to_string())
                    } else {
                        Err("invalid Authorization header format".to_string())
                    }
                }
                Err(_) => Err("invalid Authorization header".to_string()),
            }
        }
        None => Err("missing Authorization header".to_string()),
    }
}

// Endpoint handlers
async fn login(
    req: web::Json<LoginRequest>,
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    // Validate email
    if !is_valid_email(&req.email) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid email".to_string(),
        });
    }

    // Validate password
    if req.password != "r2isthebest" {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid password".to_string(),
        });
    }

    // Generate token
    let token = generate_token();
    {
        let mut app_state = state.lock().unwrap();
        app_state.tokens.insert(
            token.clone(),
            TokenData {
                created_at: Local::now(),
            },
        );
    }

    info!("Login successful for email: {}, token: {}", req.email, token);
    HttpResponse::Ok().json(LoginResponse { token })
}

async fn logout(
    req: HttpRequest,
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    // Get token from header
    let token = match get_token_from_header(&req) {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: e });
        }
    };

    // Check if token exists
    {
        let mut app_state = state.lock().unwrap();
        if !app_state.tokens.contains_key(&token) {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Invalid token".to_string(),
            });
        }
        app_state.tokens.remove(&token);
    }

    info!("Logout successful for token: {}", token);
    HttpResponse::Ok().json(LogoutResponse {
        status: "OK".to_string(),
    })
}

async fn try_luck(
    req: HttpRequest,
    state: web::Data<Mutex<AppState>>,
) -> HttpResponse {
    // Get token from header
    let token = match get_token_from_header(&req) {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: e });
        }
    };

    // Check if token exists and calculate win
    let win = {
        let mut app_state = state.lock().unwrap();
        if !app_state.tokens.contains_key(&token) {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Invalid token".to_string(),
            });
        }

        reset_daily_wins_if_needed(&mut app_state);
        let won = calculate_win(&app_state);
        if won {
            app_state.daily_wins += 1;
        }
        won
    };

    let daily_wins = state.lock().unwrap().daily_wins;
    info!(
        "Try luck for token: {}, result: {}, daily wins: {}",
        token, win, daily_wins
    );

    HttpResponse::Ok().json(TryLuckResponse { win })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let app_state = web::Data::new(Mutex::new(AppState {
        tokens: HashMap::new(),
        daily_wins: 0,
        last_reset_day: get_current_day(),
    }));

    info!("Starting backend server on port 4000");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(Logger::default())
            .route("/api/login", web::post().to(login))
            .route("/api/logout", web::post().to(logout))
            .route("/api/try_luck", web::post().to(try_luck))
    })
    .bind("0.0.0.0:4000")?
    .run()
    .await
}