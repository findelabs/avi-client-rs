use std::error::Error;
use clap::ArgMatches;
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT_ENCODING, CONTENT_TYPE};
use chrono::offset::Utc;
use chrono::NaiveDateTime;
use chrono::DateTime;
use serde_json::Value;
use async_recursion::async_recursion;
use std::sync::{Arc, RwLock};

type BoxResult<T> = Result<T,Box<dyn Error + Send + Sync>>;

#[derive(Debug, Clone)]
pub struct AviClient {
    client: reqwest::Client,
    username: String,
    password: String,
    pub controller: String,
    pub tenant: String,
    pub version: String,
    cookies: Arc<RwLock<AviCookies>>
}

#[derive(Debug, Clone)]
pub struct AviCookies {
    token_expires: i64,
    session_expires: i64,
    token: String,
    session: String
}

impl AviClient {
    pub async fn new(opts: ArgMatches<'_>) -> BoxResult<Self> {

        // Set timeout
        let timeout: u64 = opts.value_of("timeout").unwrap().parse().unwrap_or_else(|_| {
            eprintln!("Supplied timeout not in range, defaulting to 60");
            60
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::new(timeout, 0))
            .cookie_store(true)
            .danger_accept_invalid_certs(opts.is_present("insecure"))
            .build()
            .expect("Failed to build client");

        // Get username, password, and data
        let username = opts.value_of("username").unwrap().to_string();
        let password = opts.value_of("password").unwrap().to_string();
        let controller = opts.value_of("controller").unwrap().to_string();
        let tenant = opts.value_of("tenant").unwrap().to_string();
        let version = opts.value_of("version").unwrap().to_string();

        let data = format!("{{\"username\": \"{}\", \"password\": \"{}\"}}", username.clone(), password.clone());
        let uri = format!("{}/login", controller.clone());

        let response = client
            .post(uri)
            .headers(AviClient::default_headers(&version, &tenant).await?)
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

        let (session,session_max_age) = match response.cookies().find(|x| x.name() == "avi-sessionid").map(|x| (x.value().to_string(), x.max_age().unwrap().as_secs())) {
            Some(e) => {
                log::debug!("Got back sessionid of: {}", e.0);
                (e.0, e.1)
            },
            None => ("error".to_string(), 0u64)
        };

        let token_expires = Utc::now().timestamp() + token_max_age as i64;
        let session_expires = Utc::now().timestamp() + session_max_age as i64;
        let cookies = Arc::new(RwLock::new(AviCookies{ token_expires, session_expires, session, token }));
        Ok(Self { client, username, password, controller, tenant, version, cookies })

    }

    pub async fn delete(&mut self, path: &str) -> BoxResult<String> {
        self.renew().await?;
        let uri = format!("{}/{}", self.controller, path);
        let response = self.client
            .delete(uri)
            .headers(self.headers().await?)
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn post(&mut self, path: &str, body: Value) -> BoxResult<String> {
        self.renew().await?;
        let uri = format!("{}{}", self.controller, path);
        let response = self.client
            .post(uri)
            .headers(self.headers().await?)
            .body(body.to_string())
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn put(&mut self, path: &str, body: Value) -> BoxResult<String> {
        self.renew().await?;
        let uri = format!("{}{}", self.controller, path);
        let response = self.client
            .put(uri)
            .headers(self.headers().await?)
            .body(body.to_string())
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn patch(&mut self, path: &str, body: Value) -> BoxResult<String> {
        self.renew().await?;
        let uri = format!("{}{}", self.controller, path);
        let response = self.client
            .patch(uri)
            .headers(self.headers().await?)
            .body(body.to_string())
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn get(&self, path: &str) -> BoxResult<String> {
//        self.renew().await?;
        let uri = format!("{}{}", path, self.controller);
        let response = self.client
            .get(uri)
            .headers(self.headers().await?)
            .send()
            .await?;

        match response.text().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    pub async fn get_json(&mut self, path: &str) -> BoxResult<Vec<Value>> {
        self.login().await?;
        log::debug!("get_json {}", &path);
        let uri = format!("{}{}", self.controller, path);
        let vec = Vec::new();
        self.json_recursive(&uri, vec).await
    }

    pub async fn json(&self, uri: &str) -> BoxResult<Value> {
        log::debug!("Getting json output from {}", &uri);
        let response = self.client
            .get(uri)
            .headers(self.headers().await?)
            .send()
            .await?;

        match response.json().await {
            Ok(t) => Ok(t),
            Err(e) => Err(Box::new(e))
        }
    }

    #[async_recursion]
    pub async fn json_recursive(&self, path: &str, mut vec: Vec<Value>) -> BoxResult<Vec<Value>> {
        log::debug!("json_recursive: {}", &path);
        let json = self.json(path).await?;
        let next = json["next"].as_str();

        let mut results = match json["results"].as_array() {
            Some(v) => v.clone(),
            None => Vec::new()
        };

        vec.append(&mut results);

        match next {
            Some(n) => self.json_recursive(n, vec).await,
            None => Ok(vec)
        }
    } 

    pub async fn login(&mut self) -> BoxResult<String> {
        let data = format!("{{\"username\": \"{}\", \"password\": \"{}\"}}", self.username, self.password);
        let uri = format!("{}/login", self.controller.clone());

        let response = self.client
            .post(uri)
            .headers(AviClient::default_headers(&self.version, &self.tenant).await?)
            .body(data)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => log::info!("Successfully logged in to {}", self.controller.clone()),
            _ => {
                log::error!("Error logging in to controller: {}", response.status());
                return Ok("Error logging in to controller".to_owned());
            }
        };

        let (token,token_max_age) = match response.cookies().find(|x| x.name() == "csrftoken").map(|x| (x.value().to_string(), x.max_age().unwrap().as_secs())) {
            Some(e) => {
                log::debug!("Got back csrf token of: {}", e.0);
                (e.0, e.1)
            },
            None => ("error".to_string(), 0u64)
        };

        let (session,session_max_age) = match response.cookies().find(|x| x.name() == "avi-sessionid").map(|x| (x.value().to_string(), x.max_age().unwrap().as_secs())) {
            Some(e) => {
                log::debug!("Got back sessionid of: {}", e.0);
                (e.0, e.1)
            },
            None => ("error".to_string(), 0u64)
        };

        // Check out cookies
        let mut cookies = self.cookies.write().expect("Failed getting write access to cookies");

        match token == cookies.token {
            true => log::info!("csrf token is the same as before..."),
            false => { 
                log::info!("Picked up new csrf token");
                log::debug!("Registered crsf token: {}", &token);
                cookies.token = token;
            }
        };

        // Update max_age for new token
        let new_token_expires = Utc::now().timestamp() + token_max_age as i64;
        let new_session_expires = Utc::now().timestamp() + session_max_age as i64;
        cookies.token_expires = new_token_expires;
        cookies.session_expires = new_session_expires;
        cookies.session = session;

        Ok(cookies.token_expires.to_string())
    }

    pub async fn default_headers(version: &str, tenant: &str) -> BoxResult<HeaderMap> {
        // Create HeaderMap
        let mut headers = HeaderMap::new();

        // Add all headers
        headers.insert("X-Avi-Version", HeaderValue::from_str(version).unwrap());
        headers.insert("X-Avi-Tenant", HeaderValue::from_str(tenant).unwrap());
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

    pub async fn headers(&self) -> BoxResult<HeaderMap> {
        let cookies = self.cookies.read().expect("Failed reading cookies");

        // Create HeaderMap
        let mut headers = HeaderMap::new();

        log::debug!("Using X-CSRFToken of {}", cookies.token);
        log::debug!("Using X-Avi-Tenant of {}", &self.tenant);
        log::debug!("Using X-Avi-Version of {}", &self.version);

        // Add all headers
        headers.insert("X-Avi-Version", HeaderValue::from_str(&self.version).unwrap());
        headers.insert("X-Avi-Tenant", HeaderValue::from_str(&self.tenant).unwrap());
        headers.insert("X-CSRFToken", HeaderValue::from_str(&cookies.token).unwrap());
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
    pub fn expires(&self) -> BoxResult<String> {
        let cookies = self.cookies.read().expect("Failed reading cookies");
        let naive = NaiveDateTime::from_timestamp(cookies.token_expires, 0);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
        Ok(newdate.to_string())
    }

    async fn renew(&mut self) -> BoxResult<()> {
        let cookies = self.cookies.read().expect("Failed reading cookies");
        if cookies.token_expires - Utc::now().timestamp() <= 0 {
            drop(cookies);
            log::info!("token has expired, kicking off re-login function");
            self.login().await?;
        } else if cookies.session_expires - Utc::now().timestamp() <= 0 {
            drop(cookies);
            log::info!("session has expired, kicking off re-login function");
            self.login().await?;
        }
        Ok(())
    }
}
