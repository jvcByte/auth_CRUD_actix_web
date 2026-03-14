mod api;
mod shared;

use crate::api::routes::routes;

use crate::shared::config::load_env_var::AuthConfig;
use crate::shared::config::{app_state::AppState, postgres};
use actix_web::{App, HttpServer, middleware::Logger, web};
use dotenvy::dotenv;
use env_logger::Env;
use log::{error, info};
use migration::{Migrator, MigratorTrait};
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env (if present) and initialize logging.
    dotenv().ok();
    let env = Env::default().filter_or("RUST_LOG", "debug");
    env_logger::Builder::from_env(env).init();

    // Validate and cache all config from environment at startup.
    // This panics immediately if required vars (e.g. JWT_SECRET) are missing,
    // rather than surfacing as a 500 error on the first authenticated request.
    AuthConfig::init();

    // Initialize DB connection via the postgres module. This requires the
    // `DATABASE_URL` environment variable to be set. No secrets are hardcoded here.
    let db = match postgres::init_db().await {
        Ok(db) => db,
        Err(e) => {
            error!("failed to initialize database: {}", e);
            // Exit with non-zero status so orchestrators/CI notice startup failure.
            std::process::exit(1);
        }
    };
    if let Err(e) = Migrator::up(&db, None).await {
        error!("failed to run migrations: {}", e);
        std::process::exit(1);
    }

    // Build application state and start server.
    let state = web::Data::new(AppState::new(db));

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    info!("starting server at https://{}", &bind_addr);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(state.clone())
            .configure(routes)
    })
    .bind(bind_addr)?
    .run()
    .await
}
