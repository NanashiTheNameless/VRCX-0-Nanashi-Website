use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use vrcx_0_nanashi_website_protocol::api::{self, Registration, Scope};
use vrcx_0_nanashi_website_protocol::chunk::{self, ChunkBody, ChunkDraft, ChunkKind};
use vrcx_0_nanashi_website_protocol::ids::{AccountId, SourceId, VaultId};
use vrcx_0_nanashi_website_protocol::keys::{SignerKey, VaultKeys};
use vrcx_0_nanashi_website_protocol::manifest::{self, Manifest, SignerEntry, SignerKind};
use vrcx_0_nanashi_website_protocol::seal::SealPrivateKey;
use vrcx_0_nanashi_website_protocol::secret::SyncSecret;
use vrcx_0_nanashi_website_protocol::{b64, transfer};

use crate::config::Config;
use crate::crypto::ServerKeys;
use crate::db::registry::{AccountState, Registry};
use crate::routes::api_router;
use crate::routes::v1::issue_api_token;
use crate::state::{AppState, Shared};
use crate::util::now_ms;

struct Harness {
    _dir: tempfile::TempDir,
    state: Shared,
    router: Router,
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

impl Harness {
    fn new(quota: Option<u64>) -> Self {
        Self::with_registration(quota, Registration::Closed)
    }

    fn with_registration(quota: Option<u64>, registration: Registration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: dir.path().to_path_buf(),
            api_socket: dir.path().join("api.sock"),
            collector_ingest_socket: dir.path().join("collector-ingest.sock"),
            collector_socket: dir.path().join("collector.sock"),
            blob_socket: dir.path().join("blob.sock"),
            mail_socket: dir.path().join("mail.sock"),
            master_key_file: dir.path().join("unused"),
            registration,
            default_quota_bytes: quota,
            collector_default_allowed: true,
            web_origins: vec!["https://vrcx.namelessnanashi.dev".into()],
            api_origin: "https://vrcx-api.namelessnanashi.dev".into(),
            policy_url: None,
            instance_statement: None,
            instance_signature: None,
            commit: "test".into(),
        };
        let keys = ServerKeys::from_master(&[9; 32]);
        let registry =
            Registry::open(&dir.path().join("registry.db"), keys.registry_key()).unwrap();
        let state = AppState::new(
            config,
            keys,
            registry,
            crate::objects::ObjectStore::memory(),
            crate::mail::Mailer::memory(),
        );
        let router = api_router(state.clone());
        Self {
            _dir: dir,
            state,
            router,
        }
    }

    fn account(&self, quota: Option<u64>) -> AccountId {
        let id = AccountId::random().unwrap();
        self.state
            .registry()
            .create_account(
                &id,
                &format!("{}@example.com", id.as_str()),
                AccountState::Active,
                quota,
                now_ms(),
            )
            .unwrap();
        id
    }

    fn token(&self, account: &AccountId, scopes: &[Scope]) -> String {
        let row = self.state.registry().account(account).unwrap().unwrap();
        issue_api_token(
            &self.state,
            &row,
            "test PC",
            scopes,
            api::ClientKind::Desktop,
        )
        .unwrap()
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Body,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Reply {
        self.call(Method::GET, path, token, &[], Body::empty())
            .await
    }

    async fn post_json(&self, path: &str, token: Option<&str>, body: Value) -> Reply {
        let body = if matches!(path, "/web/v1/auth/signup" | "/web/v1/auth/login") {
            let mut body = body;
            if let Some(fields) = body.as_object_mut() {
                fields.insert("altcha".into(), json!(self.auth_altcha().await));
            }
            body
        } else {
            body
        };
        self.call(
            Method::POST,
            path,
            token,
            &[("content-type", "application/json")],
            Body::from(body.to_string()),
        )
        .await
    }

    async fn auth_altcha(&self) -> String {
        let challenge: altcha::Challenge =
            serde_json::from_value(self.get("/web/v1/auth/altcha/challenge", None).await.json())
                .unwrap();
        let solution = altcha::solve_challenge(altcha::SolveChallengeOptions::new(&challenge))
            .unwrap()
            .expect("ALTCHA challenge has a solution");
        let payload = altcha::Payload {
            challenge,
            solution,
        };
        data_encoding::BASE64.encode(&serde_json::to_vec(&payload).unwrap())
    }
}

const ALL: &[Scope] = &[Scope::Sync, Scope::Collector, Scope::Share, Scope::Account];

#[tokio::test]
async fn capabilities_are_public() {
    let h = Harness::new(None);
    let reply = h.get("/v1/capabilities", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["server"], api::SERVER_NAME);
    assert_eq!(
        reply.json()["limits"]["maxChunkBytes"],
        api::MAX_CHUNK_BYTES as u64
    );
    assert!(reply.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn bad_tokens_are_rejected() {
    let h = Harness::new(None);
    for token in [
        None,
        Some("garbage"),
        Some("rs1_aaaaaaaaaaaaaaaa_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ] {
        let reply = h.get("/v1/account", token).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "unauthorized");
    }
    let account = h.account(None);
    let token = h.token(&account, &[Scope::Sync]);
    let mut tampered = token.clone();
    tampered.pop();
    tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
    assert_eq!(
        h.get("/v1/account", Some(&tampered)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.get("/v1/account", Some(&token)).await.status,
        StatusCode::OK
    );
    h.state
        .registry()
        .set_state(&account, AccountState::Suspended)
        .unwrap();
    assert_eq!(
        h.get("/v1/account", Some(&token)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn scopes_are_enforced() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, &[Scope::Sync]);
    let reply = h
        .post_json(
            "/v1/vaults",
            Some(&token),
            json!({"vaultId": VaultId::random().unwrap(), "vaultPk": "", "manifestPk": ""}),
        )
        .await;
    assert_eq!(reply.code(), "forbidden_scope");
    assert_eq!(
        h.get("/v1/account/clients", Some(&token)).await.code(),
        "forbidden_scope"
    );
}

#[tokio::test]
async fn device_pairing_flow() {
    let h = Harness::new(None);
    let account = h.account(None);
    let reply = h
        .post_json(
            "/v1/device/authorize",
            None,
            json!({"deviceLabel": "Gaming PC", "requestedScopes": ["sync", "collector"]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let device_code = reply.json()["deviceCode"].as_str().unwrap().to_owned();
    let user_code = reply.json()["userCode"].as_str().unwrap().to_owned();
    assert_eq!(
        reply.json()["verificationUri"],
        "https://vrcx.namelessnanashi.dev/pair"
    );

    let poll = || h.post_json("/v1/device/token", None, json!({"deviceCode": device_code}));
    assert_eq!(poll().await.code(), "authorization_pending");
    assert_eq!(poll().await.code(), "slow_down");

    h.state
        .registry()
        .decide_pairing(&user_code, &account, Some(&[Scope::Sync]))
        .unwrap();
    let hash = h.state.keys.hmac("device-code", device_code.as_bytes());
    h.state.registry().set_pairing_poll(&hash, 0, 5).unwrap();
    let reply = poll().await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["scopes"], json!(["sync"]));
    let token = reply.json()["token"].as_str().unwrap().to_owned();
    assert_eq!(
        h.get("/v1/account", Some(&token)).await.status,
        StatusCode::OK
    );
    assert_eq!(poll().await.code(), "expired_token");
}

#[tokio::test]
async fn full_sync_round_trip_with_real_crypto() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);

    let secret = SyncSecret::generate().unwrap();
    let vault_id = VaultId::random().unwrap();
    let keys = VaultKeys::derive(&secret, vault_id);
    let public = keys.public();
    let reply = h
        .post_json(
            "/v1/vaults",
            Some(&token),
            json!({"vaultId": vault_id, "vaultPk": b64::encode(public.vault_pk.as_bytes()),
                   "manifestPk": b64::encode(public.manifest_pk.as_bytes())}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);

    let device = SignerKey::generate().unwrap();
    let mut manifest = Manifest::new(vault_id, None);
    manifest.add_signer(SignerEntry::new(
        &device.public(),
        SignerKind::Device,
        "PC",
        0,
    ));
    let sealed_manifest = manifest::seal_manifest(&manifest, &keys).unwrap();
    let path = format!("/v1/vaults/{vault_id}/manifest");
    let reply = h
        .call(
            Method::PUT,
            &path,
            Some(&token),
            &[("x-manifest-seq", "1"), ("if-match-seq", "0")],
            Body::from(sealed_manifest.clone()),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let reply = h
        .call(
            Method::PUT,
            &path,
            Some(&token),
            &[("x-manifest-seq", "1"), ("if-match-seq", "0")],
            Body::from(sealed_manifest),
        )
        .await;
    assert_eq!(reply.code(), "manifest_seq_conflict");

    let mut body = ChunkBody::default();
    body.streams.insert(
        "feed_gps".into(),
        vec![json!({"user_id": "usr_1", "location": "wrld_1:1"})],
    );
    let draft = ChunkDraft {
        vault_id,
        source_id: SourceId::random().unwrap(),
        source_seq: 1,
        kind: ChunkKind::Rows,
        created_at_ms: now_ms(),
        app_version: "test".into(),
        coverage: vec![],
        dropped_rows: 0,
        body: body.clone(),
    };
    let sealed = chunk::seal_chunk(&draft, &device, &public.vault_pk).unwrap();
    let chunk_path = format!("/v1/vaults/{vault_id}/chunks");
    let chunk_id = sealed.chunk_id.to_string();
    let chunk_headers = [("x-chunk-id", chunk_id.as_str())];
    let reply = h
        .call(
            Method::POST,
            &chunk_path,
            Some(&token),
            &chunk_headers,
            Body::from(sealed.blob.clone()),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.json()["seq"], 1);
    let retry = h
        .call(
            Method::POST,
            &chunk_path,
            Some(&token),
            &chunk_headers,
            Body::from(sealed.blob.clone()),
        )
        .await;
    assert_eq!(retry.json()["seq"], 1, "retry is idempotent");

    let reply = h.get(&path, Some(&token)).await;
    let seq: u64 = reply.headers["x-manifest-seq"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let pulled_manifest = manifest::open_manifest(&reply.body, seq, &keys, None).unwrap();
    let reply = h
        .get(
            &format!("/v1/vaults/{vault_id}/chunks:batch?after=0"),
            Some(&token),
        )
        .await;
    let frames = api::batch::decode(&reply.body).unwrap();
    assert_eq!(frames.len(), 1);
    let opened = chunk::open_chunk(
        frames[0].blob,
        vault_id,
        frames[0].chunk_id,
        &keys,
        &pulled_manifest,
    )
    .unwrap();
    assert_eq!(opened.body, body);

    let list = h
        .get(&format!("{chunk_path}?after=0"), Some(&token))
        .await
        .json();
    assert_eq!(list["maxSeq"], 1);
    assert_eq!(list["chunks"][0]["chunkId"], chunk_id);
    assert_eq!(
        h.get(&format!("{chunk_path}/1"), Some(&token)).await.body,
        sealed.blob
    );

    let info = h.get("/v1/account", Some(&token)).await.json();
    assert!(info["usageBytes"].as_u64().unwrap() > sealed.blob.len() as u64);

    let raw = std::fs::read(crate::db::account::account_db_path(
        &h.state.config.data_dir,
        &account,
    ))
    .unwrap();
    assert!(!raw.windows(8).any(|w| w == b"wrld_1:1"));
    assert!(!raw.windows(32).any(|w| w == &sealed.blob[..32]));
}

#[tokio::test]
async fn quota_limits_uploads() {
    let h = Harness::new(None);
    let account = h.account(Some(5000));
    let token = h.token(&account, ALL);
    let vault_id = VaultId::random().unwrap();
    let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), vault_id).public();
    h.post_json(
        "/v1/vaults",
        Some(&token),
        json!({"vaultId": vault_id, "vaultPk": b64::encode(keys.vault_pk.as_bytes()), "manifestPk": b64::encode(keys.manifest_pk.as_bytes())}),
    )
    .await;
    let path = format!("/v1/vaults/{vault_id}/chunks");
    let first = vrcx_0_nanashi_website_protocol::ids::ChunkId::random()
        .unwrap()
        .to_string();
    let reply = h
        .call(
            Method::POST,
            &path,
            Some(&token),
            &[("x-chunk-id", &first)],
            Body::from(vec![1_u8; 4096]),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let second = vrcx_0_nanashi_website_protocol::ids::ChunkId::random()
        .unwrap()
        .to_string();
    let reply = h
        .call(
            Method::POST,
            &path,
            Some(&token),
            &[("x-chunk-id", &second)],
            Body::from(vec![1_u8; 4096]),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reply.code(), "quota_exceeded");
}

#[tokio::test]
async fn key_transfer_through_the_server() {
    let h = Harness::new(None);
    let account = h.account(None);
    let old_device = h.token(&account, &[Scope::Sync]);
    let new_device = h.token(&account, &[Scope::Sync]);
    let secret = SyncSecret::generate().unwrap();

    let ephemeral = SealPrivateKey::generate();
    let reply = h
        .post_json(
            "/v1/transfer",
            Some(&new_device),
            json!({"epk": b64::encode(ephemeral.public().as_bytes())}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let transfer_id = reply.json()["transferId"].as_str().unwrap().to_owned();
    let code = transfer::display_code(&transfer_id, &ephemeral.public()).unwrap();
    let result_path = format!("/v1/transfer/{transfer_id}/result");
    assert_eq!(
        h.get(&result_path, Some(&new_device)).await.code(),
        "authorization_pending"
    );

    let (id, fingerprint) = transfer::parse_code(&code).unwrap();
    let epk = h
        .get(&format!("/v1/transfer/{id}"), Some(&old_device))
        .await
        .json()["epk"]
        .as_str()
        .unwrap()
        .to_owned();
    let epk = vrcx_0_nanashi_website_protocol::seal::SealPublicKey::from_bytes(
        &b64::decode(&epk).unwrap(),
    )
    .unwrap();
    let sealed = transfer::seal_secret(&epk, &fingerprint, &account, &id, &secret).unwrap();
    let reply = h
        .call(
            Method::PUT,
            &format!("/v1/transfer/{id}"),
            Some(&old_device),
            &[],
            Body::from(sealed),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);

    let reply = h.get(&result_path, Some(&new_device)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        transfer::open_secret(&ephemeral, &account, &transfer_id, &reply.body).unwrap(),
        secret
    );
    assert_eq!(
        h.get(&result_path, Some(&new_device)).await.code(),
        "transfer_not_found"
    );

    let other_account = h.account(None);
    let stranger = h.token(&other_account, &[Scope::Sync]);
    let reply = h
        .post_json(
            "/v1/transfer",
            Some(&new_device),
            json!({"epk": b64::encode(ephemeral.public().as_bytes())}),
        )
        .await;
    let fresh = reply.json()["transferId"].as_str().unwrap().to_owned();
    assert_eq!(
        h.get(&format!("/v1/transfer/{fresh}"), Some(&stranger))
            .await
            .code(),
        "transfer_not_found"
    );
}

#[tokio::test]
async fn connected_clients_and_revocation() {
    let h = Harness::new(None);
    let account = h.account(None);
    let main = h.token(&account, ALL);
    let other = h.token(&account, &[Scope::Sync]);
    let cf = [
        ("cf-connecting-ip", "203.0.113.7"),
        ("cf-ipcity", "Paris"),
        ("cf-ipcountry", "FR"),
        ("x-rs-client", "VRCX-0-Nanashi/1.0 (Windows 11; x86_64)"),
    ];
    h.call(Method::GET, "/v1/account", Some(&other), &cf, Body::empty())
        .await;
    h.call(
        Method::GET,
        "/v1/account",
        Some(&main),
        &[("cf-connecting-ip", "198.51.100.1")],
        Body::empty(),
    )
    .await;

    let clients = h
        .get("/v1/account/clients?history=true", Some(&main))
        .await
        .json();
    let clients = clients.as_array().unwrap();
    assert_eq!(clients.len(), 2);
    let other_row = clients.iter().find(|c| c["current"] == false).unwrap();
    assert_eq!(other_row["currentIp"]["ip"], "203.0.113.7");
    assert_eq!(other_row["currentIp"]["location"]["city"], "Paris");
    assert_eq!(
        other_row["clientVersion"],
        "VRCX-0-Nanashi/1.0 (Windows 11; x86_64)"
    );
    assert_eq!(other_row["activeNow"], true);
    let other_id = other_row["clientId"].as_str().unwrap().to_owned();

    let revoke = format!("/v1/account/clients/{other_id}/revoke");
    assert_eq!(
        h.post_json(&revoke, Some(&main), json!({})).await.code(),
        "reauth_required"
    );

    let totp_secret = b"0123456789abcdefghij";
    let wrapped = h.state.keys.wrap(&format!("totp:{account}"), totp_secret);
    h.state.registry().set_totp(&account, &wrapped).unwrap();
    let step = now_ms() / 1000 / 30;
    let code = {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(totp_secret).unwrap();
        mac.update(&step.to_be_bytes());
        let d = mac.finalize().into_bytes();
        let o = (d[19] & 0x0f) as usize;
        let bin = u32::from_be_bytes([d[o] & 0x7f, d[o + 1], d[o + 2], d[o + 3]]);
        format!("{:06}", bin % 1_000_000)
    };
    assert_eq!(
        h.post_json(
            "/v1/account/reauth",
            Some(&main),
            json!({"method": "totp", "code": "000000"})
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.post_json(
            "/v1/account/reauth",
            Some(&main),
            json!({"method": "totp", "code": code})
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.post_json(
            "/v1/account/reauth",
            Some(&main),
            json!({"method": "totp", "code": code})
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED,
        "codes cannot be replayed"
    );
    assert_eq!(
        h.post_json(&revoke, Some(&main), json!({})).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.get("/v1/account", Some(&other)).await.status,
        StatusCode::UNAUTHORIZED,
        "revocation is immediate"
    );

    let reply = h
        .call(
            Method::DELETE,
            "/v1/account/clients/history",
            Some(&main),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let clients = h
        .get("/v1/account/clients?history=true", Some(&main))
        .await
        .json();
    assert!(
        clients
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["history"].as_array().unwrap().is_empty())
    );
}

#[tokio::test]
async fn recovery_codes_are_single_use_for_reauth() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let (plain, hashes) = crate::recovery::generate(&h.state.keys);
    h.state
        .registry()
        .replace_recovery_codes(&account, &hashes)
        .unwrap();
    assert_eq!(
        h.state.registry().recovery_codes_left(&account).unwrap(),
        10
    );
    let written_down = plain[3].to_ascii_uppercase().replace('-', " ");
    let reauth = |code: String| {
        h.post_json(
            "/v1/account/reauth",
            Some(&token),
            json!({"method": "recovery", "code": code}),
        )
    };
    assert_eq!(
        reauth(written_down.clone()).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        reauth(written_down).await.status,
        StatusCode::UNAUTHORIZED,
        "single use"
    );
    assert_eq!(h.state.registry().recovery_codes_left(&account).unwrap(), 9);
    let (_, new_hashes) = crate::recovery::generate(&h.state.keys);
    h.state
        .registry()
        .replace_recovery_codes(&account, &new_hashes)
        .unwrap();
    assert_eq!(
        reauth(plain[4].clone()).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn owners_respect_configured_usage_limits() {
    let h = Harness::new(None);
    let account = h.account(Some(100));
    h.state.registry().set_max_vaults(&account, 1).unwrap();
    h.state
        .registry()
        .set_collector_allowed(&account, false)
        .unwrap();
    h.state
        .registry()
        .set_role(&account, crate::db::registry::Role::Owner)
        .unwrap();
    let token = h.token(&account, ALL);
    let info = h.get("/v1/account", Some(&token)).await.json();
    assert_eq!(info["quotaBytes"], 100);
    assert_eq!(info["collectorAllowed"], false);
    for index in 0..2 {
        let vault_id = VaultId::random().unwrap();
        let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), vault_id).public();
        let body = json!({"vaultId": vault_id, "vaultPk": b64::encode(keys.vault_pk.as_bytes()), "manifestPk": b64::encode(keys.manifest_pk.as_bytes())});
        let created = h.post_json("/v1/vaults", Some(&token), body).await;
        assert_eq!(
            created.status,
            if index == 0 {
                StatusCode::CREATED
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            }
        );
        if index != 0 {
            continue;
        }
        let path = format!("/v1/vaults/{vault_id}/chunks");
        let chunk_id = vrcx_0_nanashi_website_protocol::ids::ChunkId::random()
            .unwrap()
            .to_string();
        let reply = h
            .call(
                Method::POST,
                &path,
                Some(&token),
                &[("x-chunk-id", &chunk_id)],
                Body::from(vec![0_u8; 4096]),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "owners must respect their configured quota"
        );
    }
}

#[tokio::test]
async fn forbidding_sync_purges_data_and_blocks_sync() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let vault_id = VaultId::random().unwrap();
    let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), vault_id).public();
    let body = json!({"vaultId": vault_id, "vaultPk": b64::encode(keys.vault_pk.as_bytes()), "manifestPk": b64::encode(keys.manifest_pk.as_bytes())});
    assert_eq!(
        h.post_json("/v1/vaults", Some(&token), body.clone())
            .await
            .status,
        StatusCode::CREATED
    );
    {
        let row = h.state.registry().account(&account).unwrap().unwrap();
        let store = h.state.open_store(&row).unwrap();
        store
            .conn_for_tests()
            .execute("INSERT INTO collections (code, body, size, updated_at_ms) VALUES ('AbC12345', '{}', 2, 1)", [])
            .unwrap();
    }
    let old_key = h
        .state
        .registry()
        .account(&account)
        .unwrap()
        .unwrap()
        .wrapped_adk
        .unwrap();

    h.state.forbid_sync(&account, "test").unwrap();

    let reply = h.get("/v1/vaults", Some(&token)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "sync_disabled");
    assert_eq!(
        h.post_json("/v1/vaults", Some(&token), body.clone())
            .await
            .code(),
        "sync_disabled"
    );
    assert_eq!(
        h.post_json("/v1/transfer", Some(&token), json!({"epk": "x"}))
            .await
            .code(),
        "sync_disabled"
    );
    let info = h.get("/v1/account", Some(&token)).await.json();
    assert_eq!(info["syncAllowed"], false);
    assert_eq!(info["collectorAllowed"], false);

    let row = h.state.registry().account(&account).unwrap().unwrap();
    assert_ne!(
        row.wrapped_adk.clone().unwrap(),
        old_key,
        "data key replaced"
    );
    let store = h.state.open_store(&row).unwrap();
    assert!(store.vaults().unwrap().is_empty());
    assert_eq!(
        store.export_collections().unwrap().len(),
        1,
        "collections kept"
    );

    h.state.allow_sync(&account, "test").unwrap();
    assert_eq!(h.get("/v1/vaults", Some(&token)).await.json(), json!([]));
}

async fn make_vault(h: &Harness, token: &str) -> VaultId {
    let vault_id = VaultId::random().unwrap();
    let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), vault_id).public();
    let body = json!({"vaultId": vault_id, "vaultPk": b64::encode(keys.vault_pk.as_bytes()), "manifestPk": b64::encode(keys.manifest_pk.as_bytes())});
    assert_eq!(
        h.post_json(
            if token.starts_with("rsw1_") {
                "/web/v1/vaults"
            } else {
                "/v1/vaults"
            },
            Some(token),
            body,
        )
        .await
        .status,
        StatusCode::CREATED
    );
    vault_id
}

async fn upload(h: &Harness, token: &str, vault_id: &VaultId, fill: u8) -> (String, u64) {
    let chunk_id = vrcx_0_nanashi_website_protocol::ids::ChunkId::random()
        .unwrap()
        .to_string();
    let prefix = if token.starts_with("rsw1_") {
        "/web/v1"
    } else {
        "/v1"
    };
    let path = format!("{prefix}/vaults/{vault_id}/chunks");
    let reply = h
        .call(
            Method::POST,
            &path,
            Some(token),
            &[("x-chunk-id", &chunk_id)],
            Body::from(vec![fill; 4096]),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    (chunk_id, reply.json()["seq"].as_u64().unwrap())
}

#[tokio::test]
async fn objects_follow_chunks_through_compaction_and_vault_deletion() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let vault_id = make_vault(&h, &token).await;
    for fill in 1..=3 {
        upload(&h, &token, &vault_id, fill).await;
    }
    let (newest, _) = upload(&h, &token, &vault_id, 9).await;
    assert_eq!(h.state.objects.memory_keys().len(), 4);

    let single = h
        .get(&format!("/v1/vaults/{vault_id}/chunks/2"), Some(&token))
        .await;
    assert_eq!(
        single.body,
        vec![2_u8; 4096],
        "download returns the client blob"
    );

    let reply = h
        .post_json(
            &format!("/v1/vaults/{vault_id}/compact"),
            Some(&token),
            json!({"replacesUpToSeq": 3, "chunkIds": [newest]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    h.state.process_deletions().await.unwrap();
    assert_eq!(h.state.objects.memory_keys().len(), 1);
    let batch = h
        .get(
            &format!("/v1/vaults/{vault_id}/chunks:batch?after=0"),
            Some(&token),
        )
        .await;
    let frames = api::batch::decode(&batch.body).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].blob, vec![9_u8; 4096].as_slice());

    let reply = h
        .call(
            Method::DELETE,
            &format!("/v1/vaults/{vault_id}"),
            Some(&token),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    h.state.process_deletions().await.unwrap();
    assert!(h.state.objects.memory_keys().is_empty());
}

#[tokio::test]
async fn retried_upload_does_not_store_a_second_object() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let vault_id = make_vault(&h, &token).await;
    let chunk_id = vrcx_0_nanashi_website_protocol::ids::ChunkId::random()
        .unwrap()
        .to_string();
    let path = format!("/v1/vaults/{vault_id}/chunks");
    for _ in 0..2 {
        let reply = h
            .call(
                Method::POST,
                &path,
                Some(&token),
                &[("x-chunk-id", &chunk_id)],
                Body::from(vec![5_u8; 100]),
            )
            .await;
        assert_eq!(reply.json()["seq"], 1);
    }
    let reply = h
        .call(
            Method::POST,
            &path,
            Some(&token),
            &[("x-chunk-id", &chunk_id)],
            Body::from(vec![6_u8; 100]),
        )
        .await;
    assert_eq!(reply.code(), "chunk_id_exists");
    assert_eq!(h.state.objects.memory_keys().len(), 1);
}

#[tokio::test]
async fn deleting_data_removes_the_old_prefix_and_new_data_uses_a_new_one() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let vault_id = make_vault(&h, &token).await;
    upload(&h, &token, &vault_id, 1).await;
    let old_key = h.state.objects.memory_keys().remove(0);

    let reply = h
        .call(
            Method::DELETE,
            "/v1/account/data",
            Some(&token),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let vault_id = make_vault(&h, &token).await;
    upload(&h, &token, &vault_id, 2).await;
    h.state.process_deletions().await.unwrap();
    let keys = h.state.objects.memory_keys();
    assert_eq!(keys.len(), 1, "old prefix deleted, new object kept");
    assert_ne!(
        keys[0].split('/').nth(1),
        old_key.split('/').nth(1),
        "new data key, new prefix"
    );
}

#[tokio::test]
async fn orphan_sweep_removes_only_old_unreferenced_objects() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let vault_id = make_vault(&h, &token).await;
    upload(&h, &token, &vault_id, 1).await;
    let kept = h.state.objects.memory_keys().remove(0);
    let prefix = format!("{}/", kept.rsplit_once('/').unwrap().0);
    let old_orphan = format!("{prefix}{}", "a".repeat(32));
    let fresh_orphan = format!("{prefix}{}", "b".repeat(32));
    h.state
        .objects
        .memory_insert(&old_orphan, vec![1], now_ms() - 2 * crate::util::DAY_MS);
    h.state
        .objects
        .memory_insert(&fresh_orphan, vec![1], now_ms());
    assert_eq!(h.state.sweep_orphans().await.unwrap(), 1);
    let mut keys = h.state.objects.memory_keys();
    keys.sort();
    let mut expected = vec![kept, fresh_orphan];
    expected.sort();
    assert_eq!(keys, expected);
}

#[tokio::test]
async fn repeated_bad_tokens_are_rate_limited() {
    let h = Harness::new(None);
    let ip = [("cf-connecting-ip", "192.0.2.50")];
    for _ in 0..20 {
        let reply = h
            .call(
                Method::GET,
                "/v1/account",
                Some("rs1_garbage"),
                &ip,
                Body::empty(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = h
        .call(
            Method::GET,
            "/v1/account",
            Some("rs1_garbage"),
            &ip,
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(reply.headers.contains_key("retry-after"));
    let other_ip = [("cf-connecting-ip", "192.0.2.51")];
    let reply = h
        .call(
            Method::GET,
            "/v1/account",
            Some("rs1_garbage"),
            &other_ip,
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pairing_requests_are_rate_limited_per_ip() {
    let h = Harness::new(None);
    let ip = [
        ("cf-connecting-ip", "192.0.2.60"),
        ("content-type", "application/json"),
    ];
    let body = json!({"deviceLabel": "PC", "requestedScopes": ["sync"]}).to_string();
    for _ in 0..10 {
        let reply = h
            .call(
                Method::POST,
                "/v1/device/authorize",
                None,
                &ip,
                Body::from(body.clone()),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK);
    }
    let reply = h
        .call(
            Method::POST,
            "/v1/device/authorize",
            None,
            &ip,
            Body::from(body),
        )
        .await;
    assert_eq!(reply.code(), "rate_limited");
}

#[tokio::test]
async fn delete_data_shreds_the_account_file() {
    let h = Harness::new(None);
    let account = h.account(None);
    let token = h.token(&account, ALL);
    let vault_id = VaultId::random().unwrap();
    let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), vault_id).public();
    let body = json!({"vaultId": vault_id, "vaultPk": b64::encode(keys.vault_pk.as_bytes()), "manifestPk": b64::encode(keys.manifest_pk.as_bytes())});
    assert_eq!(
        h.post_json("/v1/vaults", Some(&token), body.clone())
            .await
            .status,
        StatusCode::CREATED
    );
    let path = crate::db::account::account_db_path(&h.state.config.data_dir, &account);
    assert!(path.exists());
    let old_key = h
        .state
        .registry()
        .account(&account)
        .unwrap()
        .unwrap()
        .wrapped_adk
        .unwrap();

    let reply = h
        .call(
            Method::DELETE,
            "/v1/account/data",
            Some(&token),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(!path.exists());
    assert!(
        h.state
            .registry()
            .account(&account)
            .unwrap()
            .unwrap()
            .wrapped_adk
            .is_none()
    );
    assert_eq!(h.get("/v1/vaults", Some(&token)).await.json(), json!([]));
    assert_eq!(
        h.post_json("/v1/vaults", Some(&token), body).await.status,
        StatusCode::CREATED
    );
    assert_ne!(
        h.state
            .registry()
            .account(&account)
            .unwrap()
            .unwrap()
            .wrapped_adk
            .unwrap(),
        old_key
    );
}

fn last_email(h: &Harness) -> vrcx_0_nanashi_website_protocol::mail::SendRequest {
    h.state
        .mailer
        .sent()
        .last()
        .cloned()
        .expect("an email was sent")
}

fn link_token(text: &str) -> String {
    let link = text
        .lines()
        .find(|l| l.starts_with("https://"))
        .expect("a link");
    link.split_once('#').unwrap().1.to_owned()
}

fn totp_now(secret_b32: &str) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .unwrap();
    format!("{:06}", crate::totp::code_at(&secret, now_ms() / 1000 / 30))
}

const PASSWORD: &str = "a long and unusual passphrase";

async fn sign_up_with_totp(h: &Harness, email: &str) -> (String, String, Vec<String>) {
    let reply = h
        .post_json(
            "/web/v1/auth/signup",
            None,
            json!({"email": email, "password": PASSWORD, "message": "hi"}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{:?}", reply.json());
    let mail = last_email(h);
    assert_eq!(mail.to, email);
    let token = link_token(&mail.text);
    let reply = h
        .post_json("/web/v1/auth/verify", None, json!({"token": token}))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let challenge = reply.json()["challenge"].as_str().unwrap().to_owned();
    assert_eq!(
        h.post_json("/web/v1/auth/verify", None, json!({"token": token}))
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "link works once"
    );
    let setup = h
        .post_json(
            "/web/v1/auth/enroll/totp",
            None,
            json!({"challenge": challenge}),
        )
        .await
        .json();
    let secret = setup["secret"].as_str().unwrap().to_owned();
    assert!(
        setup["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    let wrong = h
        .post_json(
            "/web/v1/auth/enroll/totp/confirm",
            None,
            json!({"challenge": challenge, "code": "000000"}),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let done = h
        .post_json(
            "/web/v1/auth/enroll/totp/confirm",
            None,
            json!({"challenge": challenge, "code": totp_now(&secret)}),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.json());
    let body = done.json();
    let codes: Vec<String> = body["recoveryCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    (body["session"].as_str().unwrap().to_owned(), secret, codes)
}

async fn approve_session(h: &Harness, session: &str) {
    let me = h.get("/web/v1/me", Some(session)).await.json();
    let account: AccountId = me["accountId"].as_str().unwrap().parse().unwrap();
    h.state.approve_account(&account, "test").unwrap();
}

#[tokio::test]
async fn signup_verify_enroll_and_approval() {
    let h = Harness::with_registration(None, Registration::Request);
    let (session, _, _) = sign_up_with_totp(&h, "new@example.com").await;
    let me = h.get("/web/v1/me", Some(&session)).await.json();
    assert_eq!(me["state"], "pending");
    assert_eq!(me["twofaMethod"], "totp");
    assert_eq!(
        me["recoveryCodesLeft"], 0,
        "pending accounts cannot access account data"
    );
    let account: AccountId = me["accountId"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        h.state
            .registry()
            .account(&account)
            .unwrap()
            .unwrap()
            .signup_message,
        "hi"
    );
    assert_eq!(
        h.get("/v1/account", Some(&session)).await.status,
        StatusCode::UNAUTHORIZED
    );
    let api = h.token(&account, ALL);
    h.state.approve_account(&account, "test").unwrap();
    assert_eq!(
        h.get("/web/v1/me", Some(&api)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.get("/web/v1/me", Some(&session)).await.json()["state"],
        "active"
    );
    assert_eq!(
        h.get("/web/v1/me", Some(&session)).await.json()["recoveryCodesLeft"],
        10
    );
}

#[tokio::test]
async fn signup_is_closed_by_default_and_does_not_reveal_existing_accounts() {
    let closed = Harness::new(None);
    let reply = closed
        .post_json(
            "/web/v1/auth/signup",
            None,
            json!({"email": "a@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(reply.code(), "feature_disabled");

    let h = Harness::with_registration(None, Registration::Request);
    sign_up_with_totp(&h, "taken@example.com").await;
    let reply = h
        .post_json(
            "/web/v1/auth/signup",
            None,
            json!({"email": "taken@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(
        reply.status,
        StatusCode::ACCEPTED,
        "same answer as a new sign-up"
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        last_email(&h).subject,
        "Sign-up attempt with your email address"
    );
    let weak = h
        .post_json(
            "/web/v1/auth/signup",
            None,
            json!({"email": "b@example.com", "password": "short"}),
        )
        .await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_in_with_totp_and_generic_errors() {
    let h = Harness::with_registration(None, Registration::Request);
    let (_, secret, _) = sign_up_with_totp(&h, "me@example.com").await;
    let wrong = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "me@example.com", "password": "not the password at all"}),
        )
        .await;
    let unknown = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "nobody@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong.json(),
        unknown.json(),
        "no difference between wrong password and unknown email"
    );

    let reply = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "ME@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(reply.json()["next"], "2fa");
    assert_eq!(reply.json()["methods"], json!(["totp", "recovery"]));
    let challenge = reply.json()["challenge"].as_str().unwrap().to_owned();
    let code = totp_now(&secret);
    let replay = h
        .post_json(
            "/web/v1/auth/login/2fa",
            None,
            json!({"challenge": challenge, "method": "totp", "code": code}),
        )
        .await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "a TOTP code cannot be used twice"
    );
}

#[tokio::test]
async fn sign_in_with_recovery_code_emails_a_notice() {
    let h = Harness::with_registration(None, Registration::Request);
    let (signup_session, _, codes) = sign_up_with_totp(&h, "me@example.com").await;
    approve_session(&h, &signup_session).await;
    let reply = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "me@example.com", "password": PASSWORD}),
        )
        .await;
    let challenge = reply.json()["challenge"].as_str().unwrap().to_owned();
    let reply = h
        .post_json(
            "/web/v1/auth/login/2fa",
            None,
            json!({"challenge": challenge, "method": "recovery", "code": codes[0]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let session = reply.json()["session"].as_str().unwrap().to_owned();
    assert_eq!(
        h.get("/web/v1/me", Some(&session)).await.json()["recoveryCodesLeft"],
        9
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let subjects: Vec<String> = h
        .state
        .mailer
        .sent()
        .iter()
        .map(|m| m.subject.clone())
        .collect();
    assert!(subjects.contains(&"A recovery code was used".to_owned()));
    assert!(subjects.contains(&"New sign-in".to_owned()));
    let again = h
        .post_json(
            "/web/v1/auth/login/2fa",
            None,
            json!({"challenge": challenge, "method": "recovery", "code": codes[1]}),
        )
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn email_two_factor_enrollment_and_sign_in() {
    let h = Harness::with_registration(None, Registration::Request);
    h.post_json(
        "/web/v1/auth/signup",
        None,
        json!({"email": "mail@example.com", "password": PASSWORD}),
    )
    .await;
    let token = link_token(&last_email(&h).text);
    let challenge = h
        .post_json("/web/v1/auth/verify", None, json!({"token": token}))
        .await
        .json()["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        h.post_json(
            "/web/v1/auth/enroll/email",
            None,
            json!({"challenge": challenge})
        )
        .await
        .status,
        StatusCode::ACCEPTED
    );
    let code = last_email(&h).text.split("code is: ").nth(1).unwrap()[..6].to_owned();
    let done = h
        .post_json(
            "/web/v1/auth/enroll/email/confirm",
            None,
            json!({"challenge": challenge, "code": code}),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.json());

    let reply = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "mail@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(reply.json()["methods"], json!(["email", "recovery"]));
    let challenge = reply.json()["challenge"].as_str().unwrap().to_owned();
    h.post_json(
        "/web/v1/auth/login/email-code",
        None,
        json!({"challenge": challenge}),
    )
    .await;
    let code = last_email(&h).text.split("code is: ").nth(1).unwrap()[..6].to_owned();
    let reply = h
        .post_json(
            "/web/v1/auth/login/2fa",
            None,
            json!({"challenge": challenge, "method": "email", "code": code}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    let session = reply.json()["session"].as_str().unwrap().to_owned();
    let me = h.get("/web/v1/me", Some(&session)).await.json();
    assert_eq!(me["twofaMethod"], "email");
    assert_eq!(me["adminAvailable"], false);
}

#[tokio::test]
async fn password_reset_requires_second_factor_and_ends_sessions() {
    let h = Harness::with_registration(None, Registration::Request);
    let (old_session, _, codes) = sign_up_with_totp(&h, "reset@example.com").await;
    approve_session(&h, &old_session).await;
    assert_eq!(
        h.post_json(
            "/web/v1/auth/reset",
            None,
            json!({"email": "nobody@example.com"})
        )
        .await
        .status,
        StatusCode::ACCEPTED
    );
    let sent_before = h.state.mailer.sent().len();
    assert_eq!(
        h.post_json(
            "/web/v1/auth/reset",
            None,
            json!({"email": "reset@example.com"})
        )
        .await
        .status,
        StatusCode::ACCEPTED
    );
    assert_eq!(h.state.mailer.sent().len(), sent_before + 1);
    let token = link_token(&last_email(&h).text);
    let new_password = "another long passphrase here";
    let reply = h
        .post_json(
            "/web/v1/auth/reset/finish",
            None,
            json!({"token": token, "password": new_password}),
        )
        .await;
    assert_eq!(reply.json()["next"], "2fa");
    let challenge = reply.json()["challenge"].as_str().unwrap().to_owned();
    let still_old = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "reset@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(still_old.status, StatusCode::OK);
    let reply = h
        .post_json(
            "/web/v1/auth/login/2fa",
            None,
            json!({"challenge": challenge, "method": "recovery", "code": codes[2]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(
        h.get("/web/v1/me", Some(&old_session)).await.status,
        StatusCode::UNAUTHORIZED,
        "old sessions ended"
    );
    let new_login = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "reset@example.com", "password": new_password}),
        )
        .await;
    assert_eq!(new_login.status, StatusCode::OK);
    let old_login = h
        .post_json(
            "/web/v1/auth/login",
            None,
            json!({"email": "reset@example.com", "password": PASSWORD}),
        )
        .await;
    assert_eq!(old_login.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reauth_regenerates_recovery_codes_and_sign_out() {
    let h = Harness::with_registration(None, Registration::Request);
    let (session, _, codes) = sign_up_with_totp(&h, "me@example.com").await;
    let reply = h
        .post_json("/web/v1/recovery-codes", Some(&session), json!({}))
        .await;
    assert_eq!(reply.code(), "account_not_active");
    approve_session(&h, &session).await;
    let reply = h
        .post_json("/web/v1/recovery-codes", Some(&session), json!({}))
        .await;
    assert_eq!(reply.code(), "reauth_required");
    let reply = h
        .post_json(
            "/web/v1/reauth",
            Some(&session),
            json!({"method": "recovery", "code": codes[0]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let me = h.get("/web/v1/me", Some(&session)).await.json();
    assert!(me["recentAuthUntilMs"].as_i64().unwrap() > now_ms());
    assert!(
        me["recentTotpUntilMs"].as_i64().unwrap() < now_ms(),
        "a recovery code is not a TOTP code"
    );
    let fresh = h
        .post_json("/web/v1/recovery-codes", Some(&session), json!({}))
        .await
        .json();
    assert_eq!(fresh["recoveryCodes"].as_array().unwrap().len(), 10);
    let old = h
        .post_json(
            "/web/v1/reauth",
            Some(&session),
            json!({"method": "recovery", "code": codes[1]}),
        )
        .await;
    assert_eq!(
        old.status,
        StatusCode::UNAUTHORIZED,
        "old codes stop working"
    );
    let reply = h
        .call(
            Method::DELETE,
            "/web/v1/session",
            Some(&session),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get("/web/v1/me", Some(&session)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

fn web_session(h: &Harness, recent: bool) -> (AccountId, String) {
    let account = h.account(None);
    let row = h.state.registry().account(&account).unwrap().unwrap();
    let session = crate::routes::web::issue_session(&h.state, &row, "Firefox on Linux").unwrap();
    if recent {
        let id = vrcx_0_nanashi_website_protocol::token::parse(
            &session,
            vrcx_0_nanashi_website_protocol::token::TokenKind::Session,
        )
        .unwrap()
        .id;
        h.state
            .registry()
            .set_recent_auth(&id, now_ms() + 600_000)
            .unwrap();
    }
    (account, session)
}

#[tokio::test]
async fn cors_only_for_website_origins_and_only_on_web_routes() {
    let h = Harness::new(None);
    async fn preflight(h: &Harness, origin: &str, path: &str) -> Reply {
        let headers = [
            ("origin", origin),
            ("access-control-request-method", "GET"),
            ("access-control-request-headers", "authorization"),
        ];
        h.call(Method::OPTIONS, path, None, &headers, Body::empty())
            .await
    }
    let allowed = preflight(&h, "https://vrcx.namelessnanashi.dev", "/web/v1/me").await;
    assert_eq!(
        allowed.headers.get("access-control-allow-origin").unwrap(),
        "https://vrcx.namelessnanashi.dev"
    );
    let other = preflight(&h, "https://evil.example", "/web/v1/me").await;
    assert!(other.headers.get("access-control-allow-origin").is_none());
    let app_api = preflight(&h, "https://vrcx.namelessnanashi.dev", "/v1/account").await;
    assert!(app_api.headers.get("access-control-allow-origin").is_none());
    let public = preflight(
        &h,
        "https://vrcx.namelessnanashi.dev",
        "/public/v1/collections",
    )
    .await;
    assert_eq!(
        public.headers.get("access-control-allow-origin").unwrap(),
        "https://vrcx.namelessnanashi.dev"
    );
}

#[tokio::test]
async fn website_sessions_use_the_shared_routes_with_extra_checks() {
    let h = Harness::new(None);
    let (account, session) = web_session(&h, false);
    let vault = make_vault(&h, &session).await;
    upload(&h, &session, &vault, 3).await;
    let vaults = h.get("/web/v1/vaults", Some(&session)).await.json();
    assert_eq!(vaults[0]["vaultId"], vault.to_string());
    let batch = h
        .get(
            &format!("/web/v1/vaults/{vault}/chunks:batch?after=0"),
            Some(&session),
        )
        .await;
    assert_eq!(api::batch::decode(&batch.body).unwrap().len(), 1);
    let reply = h
        .call(
            Method::DELETE,
            &format!("/web/v1/vaults/{vault}"),
            Some(&session),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.code(), "reauth_required");
    let reply = h
        .call(
            Method::DELETE,
            "/web/v1/account/data",
            Some(&session),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.code(), "reauth_required");
    h.state
        .registry()
        .set_state(&account, AccountState::Pending)
        .unwrap();
    assert_eq!(
        h.get("/web/v1/vaults", Some(&session)).await.code(),
        "account_not_active"
    );
    assert_eq!(
        h.get("/web/v1/me", Some(&session)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn website_admin_routes_require_recent_totp_and_respect_roles() {
    let h = Harness::new(None);
    let (admin_id, session) = web_session(&h, false);
    h.state
        .registry()
        .set_role(&admin_id, crate::db::registry::Role::Admin)
        .unwrap();
    let admin_session_id = vrcx_0_nanashi_website_protocol::token::parse(
        &session,
        vrcx_0_nanashi_website_protocol::token::TokenKind::Session,
    )
    .unwrap()
    .id;
    let target_id = h.account(None);

    assert_eq!(
        h.get("/web/v1/admin/accounts", Some(&session)).await.code(),
        "totp_required"
    );
    h.state.registry().set_totp(&admin_id, &[7; 48]).unwrap();
    assert_eq!(
        h.get("/web/v1/admin/accounts", Some(&session)).await.code(),
        "totp_reauth_required"
    );
    h.state
        .registry()
        .set_recent_totp(&admin_session_id, now_ms() + 600_000)
        .unwrap();

    let listed = h.get("/web/v1/admin/accounts", Some(&session)).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert!(
        listed
            .json()
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["accountId"] == target_id.to_string())
    );
    let role = h
        .call(
            Method::PUT,
            &format!("/web/v1/admin/accounts/{target_id}/role"),
            Some(&session),
            &[("content-type", "application/json")],
            Body::from(r#"{"role":"admin"}"#),
        )
        .await;
    assert_eq!(role.code(), "owner_required");
    assert_eq!(
        h.state
            .registry()
            .account(&target_id)
            .unwrap()
            .unwrap()
            .role,
        crate::db::registry::Role::User
    );
    h.state
        .registry()
        .set_state(&target_id, AccountState::Pending)
        .unwrap();
    let resume = h
        .post_json(
            &format!("/web/v1/admin/accounts/{target_id}/resume"),
            Some(&session),
            json!({}),
        )
        .await;
    assert_eq!(resume.status, StatusCode::CONFLICT);
    assert_eq!(
        h.state
            .registry()
            .account(&target_id)
            .unwrap()
            .unwrap()
            .state,
        AccountState::Pending
    );
}

#[tokio::test]
async fn website_admin_invites_and_persisted_settings_work() {
    let h = Harness::new(None);
    let (admin_id, session) = web_session(&h, false);
    h.state
        .registry()
        .set_role(&admin_id, crate::db::registry::Role::Admin)
        .unwrap();
    let session_id = vrcx_0_nanashi_website_protocol::token::parse(
        &session,
        vrcx_0_nanashi_website_protocol::token::TokenKind::Session,
    )
    .unwrap()
    .id;
    h.state.registry().set_totp(&admin_id, &[3; 48]).unwrap();
    h.state
        .registry()
        .set_recent_totp(&session_id, now_ms() + 600_000)
        .unwrap();

    let settings = h
        .call(
            Method::PUT,
            "/web/v1/admin/settings",
            Some(&session),
            &[("content-type", "application/json")],
            Body::from(r#"{"registration":"request","defaultQuota":"64MiB","collectorDefaultAllowed":false}"#),
        )
        .await;
    assert_eq!(settings.status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get("/v1/capabilities", None).await.json()["registration"],
        "request"
    );

    let before = h.state.mailer.sent().len();
    let invited = h
        .post_json(
            "/web/v1/admin/invites",
            Some(&session),
            json!({"email":"invite@example.com"}),
        )
        .await;
    assert_eq!(invited.status, StatusCode::ACCEPTED);
    let account = h
        .state
        .registry()
        .account_by_email("invite@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(account.state, AccountState::Unverified);
    assert_eq!(account.quota_bytes, Some(64 << 20));
    assert!(!account.collector_allowed);
    assert_eq!(h.state.mailer.sent().len(), before + 1);

    let changed = h
        .call(
            Method::PUT,
            &format!("/web/v1/admin/accounts/{}/limits", account.account_id),
            Some(&session),
            &[("content-type", "application/json")],
            Body::from(r#"{"quota":"32MiB","maxVaults":2}"#),
        )
        .await;
    assert_eq!(changed.status, StatusCode::NO_CONTENT);
    let updated = h
        .state
        .registry()
        .account(&account.account_id)
        .unwrap()
        .unwrap();
    assert_eq!(updated.quota_bytes, Some(32 << 20));
    assert_eq!(updated.max_vaults, 2);
    assert!(
        h.get("/web/v1/admin/audit", Some(&session))
            .await
            .json()
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["action"] == "account-limits")
    );
    crate::cli::run(
        &h.state,
        crate::cli::AdminCommand::Settings(crate::cli::SettingsCommand::Set {
            registration: Some(crate::cli::RegistrationArg::Closed),
            default_quota: Some("128MiB".into()),
            collector_default: Some(crate::cli::OnOff::On),
        }),
    )
    .unwrap();
    assert_eq!(
        h.get("/v1/capabilities", None).await.json()["registration"],
        "closed"
    );
}

#[tokio::test]
async fn collections_round_trip_between_owner_and_public_routes() {
    let h = Harness::new(None);
    let account = h.account(None);
    let share = h.token(&account, &[Scope::Share]);
    let payload = json!({
        "id":"", "title":"Favorite worlds", "note":"A few places", "author_name":"N",
        "author_profile":null, "category":"Hangout", "listed":false, "updated_at":0,
        "worlds":[{"world_id":"wrld_example", "name":"World", "author_name":"Maker", "image_url":"", "description":"", "comment":"Visit"}]
    });
    let created = h
        .post_json("/v1/collections", Some(&share), payload.clone())
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
    let created_body = created.json();
    let code = created_body["code"].as_str().unwrap();
    assert_eq!(
        created_body["url"],
        format!("https://vrcx.namelessnanashi.dev/c/{code}")
    );
    assert_eq!(
        h.get(&format!("/public/v1/collections/{code}"), None)
            .await
            .json()["title"],
        "Favorite worlds"
    );
    assert_eq!(
        h.get("/public/v1/collections", None)
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let mut listed = h
        .get(&format!("/public/v1/collections/{code}"), None)
        .await
        .json();
    listed["listed"] = json!(true);
    let updated = h
        .call(
            Method::PUT,
            &format!("/v1/collections/{code}"),
            Some(&share),
            &[("content-type", "application/json")],
            Body::from(listed.to_string()),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(
        h.get("/public/v1/collections", None)
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        h.get("/v1/collections", Some(&share))
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let deleted = h
        .call(
            Method::DELETE,
            &format!("/v1/collections/{code}"),
            Some(&share),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get(&format!("/public/v1/collections/{code}"), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn admin_backup_copies_encrypted_registry_and_account_databases() {
    let h = Harness::new(None);
    let account_id = h.account(None);
    let account = h.state.registry().account(&account_id).unwrap().unwrap();
    let (_store, keys) = h.state.open_store_with_keys(&account).unwrap();
    let directory = h._dir.path().join("backup");
    crate::cli::run(
        &h.state,
        crate::cli::AdminCommand::Backup {
            directory: directory.clone(),
        },
    )
    .unwrap();

    let registry =
        crate::db::open_encrypted(&directory.join("registry.db"), h.state.keys.registry_key())
            .unwrap();
    let count: i64 = registry
        .query_row("SELECT count(*) FROM accounts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let account_backup = crate::db::open_encrypted(
        &directory.join("accounts").join(format!("{account_id}.db")),
        keys.db_key(),
    )
    .unwrap();
    let version: i64 = account_backup
        .query_row("SELECT v FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert!(version > 0);
}

#[test]
fn cli_invites_create_unverified_accounts_and_send_links() {
    let h = Harness::new(None);
    crate::cli::run(
        &h.state,
        crate::cli::AdminCommand::Users(crate::cli::UsersCommand::Invite {
            email: "cli-invite@example.com".into(),
            role: crate::cli::RoleArg::Admin,
            quota: Some("32MiB".into()),
        }),
    )
    .unwrap();
    let account = h
        .state
        .registry()
        .account_by_email("cli-invite@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(account.state, AccountState::Unverified);
    assert_eq!(account.role, crate::db::registry::Role::Admin);
    assert_eq!(account.quota_bytes, Some(32 << 20));
    let email = last_email(&h);
    assert!(email.subject.contains("invited"));
    assert!(email.text.contains("/invite#"));
}

#[tokio::test]
async fn pairing_is_approved_on_the_website() {
    let h = Harness::new(None);
    let (_, session) = web_session(&h, true);
    let started = h
        .post_json(
            "/v1/device/authorize",
            None,
            json!({"deviceLabel": "Gaming PC", "requestedScopes": ["sync", "collector", "share"]}),
        )
        .await
        .json();
    let user_code = started["userCode"].as_str().unwrap().to_owned();
    let device_code = started["deviceCode"].as_str().unwrap().to_owned();
    let typed = user_code.to_ascii_lowercase().replace('-', "");
    let info = h
        .get(&format!("/web/v1/pair/{typed}"), Some(&session))
        .await
        .json();
    assert_eq!(info["deviceLabel"], "Gaming PC");
    let reply = h
        .post_json(
            &format!("/web/v1/pair/{typed}/approve"),
            Some(&session),
            json!({"scopes": ["sync"]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let hash = h.state.keys.hmac("device-code", device_code.as_bytes());
    h.state.registry().set_pairing_poll(&hash, 0, 5).unwrap();
    let token = h
        .post_json("/v1/device/token", None, json!({"deviceCode": device_code}))
        .await
        .json();
    assert_eq!(
        token["scopes"],
        json!(["sync"]),
        "the user reduced the scopes"
    );
    assert_eq!(
        h.get(&format!("/web/v1/pair/{typed}"), Some(&session))
            .await
            .code(),
        "pairing_not_found"
    );
}

#[tokio::test]
async fn manual_tokens_need_recent_auth() {
    let h = Harness::new(None);
    let (_, stale) = web_session(&h, false);
    let reply = h
        .post_json(
            "/web/v1/tokens",
            Some(&stale),
            json!({"label": "server", "scopes": ["sync"]}),
        )
        .await;
    assert_eq!(reply.code(), "reauth_required");
    let (_, fresh) = web_session(&h, true);
    let reply = h
        .post_json(
            "/web/v1/tokens",
            Some(&fresh),
            json!({"label": "server", "scopes": ["sync"]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let token = reply.json()["token"].as_str().unwrap().to_owned();
    assert_eq!(
        h.get("/v1/account", Some(&token)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn key_envelopes_are_stored_fetched_rate_limited_and_deleted() {
    use vrcx_0_nanashi_website_protocol::envelope;
    let h = Harness::new(None);
    let (account, session) = web_session(&h, true);
    let secret = SyncSecret::generate().unwrap();
    let legacy_passkey = envelope::seal_with_prf(
        &secret,
        &account,
        "Laptop passkey",
        b"cred",
        &[1; 32],
        &[2; 32],
        0,
    )
    .unwrap();
    let rejected = h
        .post_json(
            "/web/v1/envelopes",
            Some(&session),
            serde_json::to_value(&legacy_passkey).unwrap(),
        )
        .await;
    assert_eq!(
        rejected.status,
        StatusCode::BAD_REQUEST,
        "new passkey envelopes are disabled"
    );
    let passphrase = envelope::seal_with_passphrase(
        &secret,
        &account,
        "Laptop recovery",
        "a long recovery phrase",
        false,
        0,
    )
    .unwrap();
    let body = serde_json::to_string(&passphrase).unwrap();
    let reply = h
        .call(
            Method::POST,
            "/web/v1/envelopes",
            Some(&session),
            &[("content-type", "application/json")],
            Body::from(body.clone()),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let list = h.get("/web/v1/envelopes", Some(&session)).await.json();
    assert_eq!(list[0]["kind"], "passphrase");
    assert_eq!(list[0]["label"], "Laptop recovery");
    let path = format!("/web/v1/envelopes/{}", passphrase.envelope_id);
    let fetched: envelope::KeyEnvelope =
        serde_json::from_slice(&h.get(&path, Some(&session)).await.body).unwrap();
    assert_eq!(
        envelope::open_with_passphrase(&fetched, &account, "a long recovery phrase").unwrap(),
        secret,
        "the server returns it unchanged"
    );
    for _ in 0..9 {
        assert_eq!(h.get(&path, Some(&session)).await.status, StatusCode::OK);
    }
    assert_eq!(
        h.get(&path, Some(&session)).await.code(),
        "rate_limited",
        "10 downloads per day"
    );

    let mut weak = serde_json::to_value(&passphrase).unwrap();
    weak["lock"] = json!({"kind": "passphrase", "cost": {"mKib": 8, "t": 1, "p": 1}, "salt": b64::encode(&[0; 16]), "generated": false});
    weak["envelopeId"] = json!(b64::encode(&[9; 16]));
    let reply = h
        .call(
            Method::POST,
            "/web/v1/envelopes",
            Some(&session),
            &[],
            Body::from(weak.to_string()),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    let reply = h
        .call(
            Method::DELETE,
            "/web/v1/envelopes",
            Some(&session),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get("/web/v1/envelopes", Some(&session)).await.json(),
        json!([])
    );
}

#[tokio::test]
async fn deleting_the_account_from_the_website() {
    let h = Harness::new(None);
    let (account, session) = web_session(&h, true);
    let vault = make_vault(&h, &session).await;
    upload(&h, &session, &vault, 1).await;
    let reply = h
        .call(
            Method::DELETE,
            "/web/v1/account",
            Some(&session),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(h.state.registry().account(&account).unwrap().is_none());
    h.state.process_deletions().await.unwrap();
    assert!(h.state.objects.memory_keys().is_empty());
    assert_eq!(
        h.get("/web/v1/me", Some(&session)).await.status,
        StatusCode::UNAUTHORIZED
    );

    let (owner, owner_session) = web_session(&h, true);
    h.state
        .registry()
        .set_role(&owner, crate::db::registry::Role::Owner)
        .unwrap();
    let reply = h
        .call(
            Method::DELETE,
            "/web/v1/account",
            Some(&owner_session),
            &[],
            Body::empty(),
        )
        .await;
    assert_eq!(reply.code(), "owner_cli_only");
}
