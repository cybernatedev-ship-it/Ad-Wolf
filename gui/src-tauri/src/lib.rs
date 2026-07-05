use std::sync::Arc;

use dns_filter_core::QueryLogger;
use dns_filter_storage::QueryStore;
use tauri::State;

/// Application state shared across Tauri commands
pub struct AppState {
    pub stats: Arc<QueryLogger>,
    pub store: QueryStore,
}

/// Get query statistics (blocked, allowed, cached totals)
#[tauri::command]
fn get_stats(state: State<AppState>) -> Result<serde_json::Value, String> {
    let stats = state.stats.get_stats();
    Ok(serde_json::json!({
        "total": stats.total_queries,
        "blocked": stats.total_blocked,
        "allowed": stats.total_allowed,
        "cached": stats.cache_hits,
    }))
}

/// Get recent log entries
#[tauri::command]
fn get_recent(
    state: State<AppState>,
    limit: Option<usize>,
) -> Result<Vec<serde_json::Value>, String> {
    let entries = state
        .store
        .recent(limit.unwrap_or(50))
        .map_err(|e| e.to_string())?;
    let result: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "domain": e.domain,
                "query_type": e.query_type,
                "action": e.action,
                "upstream_ms": e.upstream_ms,
                "client_ip": e.client_ip,
            })
        })
        .collect();
    Ok(result)
}

/// Get top blocked domains
#[tauri::command]
fn get_top_blocked(
    state: State<AppState>,
    limit: Option<usize>,
) -> Result<Vec<serde_json::Value>, String> {
    let entries = state
        .store
        .top_blocked(limit.unwrap_or(10))
        .map_err(|e| e.to_string())?;
    let result: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|(domain, count)| serde_json::json!({"domain": domain, "count": count}))
        .collect();
    Ok(result)
}

/// Get summary stats since a given timestamp
#[tauri::command]
fn get_stats_since(state: State<AppState>, since: i64) -> Result<serde_json::Value, String> {
    let stats = state.store.stats_since(since).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "total": stats.total,
        "blocked": stats.blocked,
        "allowed": stats.allowed,
        "cached": stats.cached,
        "errors": stats.errors,
    }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Open in-memory store for now; real app would use a file path
    let store = QueryStore::in_memory().expect("failed to create query store");
    let stats = Arc::new(QueryLogger::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState { stats, store })
        .invoke_handler(tauri::generate_handler![
            get_stats,
            get_recent,
            get_top_blocked,
            get_stats_since,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
