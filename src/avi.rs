use std::error::Error;
use clap::ArgMatches;
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT_ENCODING, CONTENT_TYPE};
use chrono::offset::Utc;
use chrono::NaiveDateTime;
use chrono::DateTime;
use serde_json::Value;
use async_recursion::async_recursion;

type BoxResult<T> = Result<T,Box<dyn Error + Send + Sync>>;

#[derive(Debug, Clone)]
pub struct AviClient {
    client: reqwest::Client,
    expires: i64,
    username: String,
    password: String,
    controller: String,
    token: String,
    session: String
}

impl AviClient {
    pub async fn new(opts: ArgMatches<'_>) -> BoxResult<Self> {

        let client = reqwest::Client::builder()
            .timeout(Duration::new(60, 0))
            .cookie_store(true)
            .danger_accept_invalid_certs(opts.value_of("insecure").unwrap().parse()?)
            .build()
            .expect("Failed to build client");

        // Get username, password, and data
        let username = opts.value_of("username").unwrap().to_string();
        let password = opts.value_of("password").unwrap().to_string();
        let controller = opts.value_of("controller").unwrap().to_string();
        let data = format!("{{\"username\": \"{}\", \"password\": \"{}\"}}", username.clone(), password.clone());
        let uri = format!("{}/login", controller.clone());

        let response = client
            .post(uri)
            .headers(AviClient::headers("missing").await?)
            .body(data)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => log::info!("Successfully logged in to {}", controller.clone()),
            _ => panic!("Error logging in to controller: {}", response.status())
        };

        let (token,token_max_age) = match response.cookies().find(|x| x.name() == "csrftoken").map(|x| (x.value().to_string(), x.max_age().unwrap().as_secs())) {
            Some(e) => {
                log::debug!("Got back csrf token of: {}", e.0);
                (e.0, e.1)
            },
            None => ("error".to_string(), 0u64)
        };

        let (session,_session_max_age) = match response.cookies().find(|x| x.name() == "avi-sessionid").map(|x| (x.value().to_string(), x.max_age().unwrap().as_secs())) {
            Some(e) => {
                log::debug!("Got back sessionid of: {}", e.0);
                (e.0, e.1)
            },
            None => ("error".to_string(), 0u64)
        };

        let expires = Utc::now().timestamp() + token_max_age as i64;
        Ok(Self { client, expires, username, password, controller, session, token })

    }

    pub async fn delete(&mut self, path: &str) -> BoxResult<String> {
        self.renew().await?;
        let uri = format!("{}/{}", path, self.controller);
        let response = self.client
            .delete(uri)
            .headers(AviClient::headers(&self.token).await?)
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn post(&self, path: &str, body: Value) -> BoxResult<String> {
        let uri = format!("{}/{}", path, self.controller);
        let response = self.client
            .post(uri)
            .headers(AviClient::headers(&self.token).await?)
            .body(body.to_string())
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn put(&self, path: &str, body: Value) -> BoxResult<String> {
        let uri = format!("{}/{}", path, self.controller);
        let response = self.client
            .put(uri)
            .headers(AviClient::headers(&self.token).await?)
            .body(body.to_string())
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn patch(&self, path: &str, body: Value) -> BoxResult<String> {
        let uri = format!("{}/{}", path, self.controller);
        let response = self.client
            .patch(uri)
            .headers(AviClient::headers(&self.token).await?)
            .body(body.to_string())
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn get(&self, path: &str) -> BoxResult<String> {
        let uri = format!("{}/{}", path, self.controller);
        let response = self.client
            .get(uri)
            .headers(AviClient::headers(&self.token).await?)
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn json(&self, path: &str) -> BoxResult<Value> {
        let uri = format!("{}/{}", self.controller.clone(), path);
        log::info!("Getting json output from {}", &uri);
        let response = self.client
            .get(uri)
            .headers(AviClient::headers(&self.token).await?)
            .send()
            .await?;

        match response.json().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    #[async_recursion]
    pub async fn get_json(&self, path: &str, mut vec: Vec<Value>) -> BoxResult<Vec<Value>> {
        log::info!("Getting here: {}", &path);
        let json = self.json(path).await?;
        let next = json["next"].as_str();

        let mut results = match json["results"].as_array() {
            Some(v) => v.clone(),
            None => Vec::new()
        };

        vec.append(&mut results);

        match next {
            Some(n) => self.get_json(n, vec).await,
            None => Ok(vec)
        }
    } 

    pub async fn login(&mut self) -> BoxResult<String> {
        let data = format!("{{\"username\": \"{}\", \"password\": \"{}\"}}", self.username, self.password);
        let uri = format!("{}/login", self.controller.clone());

        let response = self.client
            .post(uri)
            .headers(AviClient::headers(&self.token).await?)
            .body(data)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => log::info!("Successfully logged in to {}", self.controller.clone()),
            _ => log::error!("Error logging in to controller: {}", response.status())
        };

        // Will need to handle bad logins somehow
        let expires = match response.cookies().find(|x| x.name() == "avi-sessionid").map(|x| (x.value().to_string(), x.max_age().unwrap().as_secs())) {
            Some(e) => {
                match e.0 == self.token {
                    true => log::info!("csrf token is the same as before..."),
                    false => { 
                        log::info!("Picked up new csrf token");
                        log::debug!("Registered crsf token: {}", e.0);
                        self.token = e.0;
                    }
                };

                // Update max_age for new token
                let new_expires = Utc::now().timestamp() + e.1 as i64;
                self.expires = new_expires;
                self.expires
            },
            None => {
                log::info!("Failed getting csrf token");
                self.expires = 0;
                self.expires
            }
        };
        Ok(format!("{}", expires))
    }

    pub async fn headers(token: &str) -> BoxResult<HeaderMap> {
        // Create HeaderMap
        let mut headers = HeaderMap::new();

        log::debug!("Using X-CSRFToken of {}", &token);

        // Add all headers
        headers.insert("X-Avi-Version", HeaderValue::from_str("21.1.3").unwrap());
        headers.insert("X-Avi-Tenant", HeaderValue::from_str("ebdc_kub3_dds_np").unwrap());
        headers.insert("X-CSRFToken", HeaderValue::from_str(token).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_str("hyper-rs").unwrap());
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/json").unwrap(),
        );
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_str("application/json").unwrap(),
        );

        // Return headers
        Ok(headers)
    }

    // Return back the time in UTC that the cookie will expire
    pub fn expires(&self) -> String {
        let naive = NaiveDateTime::from_timestamp(self.expires, 0);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
        newdate.to_string()
    }

    async fn renew(&mut self) -> BoxResult<()> {
        if self.expires - Utc::now().timestamp() <= 0 {
            log::info!("renew function kicking off re-login function");
            self.login().await?;
        }
        Ok(())
    }
}
