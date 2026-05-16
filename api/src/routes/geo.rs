use crate::routes::{api_err, ApiResponse, AppState};
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct GeoQuery {
    pub ips: String, // comma-separated IPs
}

#[derive(Serialize, Deserialize)]
struct IpApiResult {
    status: String,
    country: String,
    #[serde(rename = "countryCode")]
    country_code: String,
    city: String,
    lat: f64,
    lon: f64,
    query: String,
}

#[derive(Serialize, Deserialize)]
struct IpApiBatchItem {
    query: String,
    fields: String,
}

/// Geo-IP lookup via ip-api.com proxy (avoids CORS issues).
/// GET /api/geo-lookup?ips=1.1.1.1,8.8.8.8
pub async fn geo_lookup(state: web::Data<AppState>, q: web::Query<GeoQuery>) -> HttpResponse {
    let ips: Vec<&str> = q
        .ips
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if ips.is_empty() {
        return HttpResponse::BadRequest().json(api_err("no IPs provided"));
    }

    if ips.len() == 1 {
        let url = format!(
            "https://ip-api.com/json/{}?fields=country,countryCode,city,lat,lon",
            ips[0]
        );
        match state.http.get(&url).send().await {
            Ok(resp) => match resp.json::<IpApiResult>().await {
                Ok(r) if r.status != "fail" => {
                    HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({
                        r.query: { "country": r.country, "countryCode": r.country_code, "city": r.city, "lat": r.lat, "lon": r.lon }
                    })))
                }
                _ => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({}))),
            },
            Err(e) => HttpResponse::InternalServerError().json(api_err(&format!("geo: {}", e))),
        }
    } else {
        let body: Vec<IpApiBatchItem> = ips
            .iter()
            .map(|ip| IpApiBatchItem {
                query: ip.to_string(),
                fields: "country,countryCode,city,lat,lon".into(),
            })
            .collect();

        match state
            .http
            .post("https://ip-api.com/batch")
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => match resp.json::<Vec<IpApiResult>>().await {
                Ok(results) => {
                    let mut map = serde_json::Map::new();
                    for r in results {
                        if r.status != "fail" {
                            map.insert(
                                r.query.clone(),
                                serde_json::json!({
                                    "country": r.country, "countryCode": r.country_code,
                                    "city": r.city, "lat": r.lat, "lon": r.lon
                                }),
                            );
                        }
                    }
                    HttpResponse::Ok().json(ApiResponse::ok(serde_json::Value::Object(map)))
                }
                Err(_) => HttpResponse::Ok().json(ApiResponse::ok(serde_json::json!({}))),
            },
            Err(e) => {
                HttpResponse::InternalServerError().json(api_err(&format!("geo batch: {}", e)))
            }
        }
    }
}
