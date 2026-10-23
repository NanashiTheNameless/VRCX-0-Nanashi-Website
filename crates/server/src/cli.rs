use clap::{Args, Subcommand, ValueEnum};
use std::cell::Cell;
use std::path::PathBuf;
use vrcx_0_nanashi_website_protocol::api::{ClientKind, Scope};
use vrcx_0_nanashi_website_protocol::ids::AccountId;
use vrcx_0_nanashi_website_protocol::token;

use crate::config::{format_size, parse_size, validate_quota};
use crate::db::registry::{AccountRow, AccountState, Role};
use crate::http::ApiErr;
use crate::routes::v1::issue_api_token;
use crate::state::{AppState, Shared};
use crate::util::now_epoch;

const ACTOR: &str = "cli";

thread_local! {
    static JSON_OUTPUT: Cell<bool> = const { Cell::new(false) };
}

macro_rules! cli_println {
    ($($arg:tt)*) => {{
        let message = format!($($arg)*);
        JSON_OUTPUT.with(|json| {
            if json.get() {
                println!("{{\"message\":{}}}", serde_json::to_string(&message).expect("string serializes"));
            } else {
                println!("{message}");
            }
        });
    }};
}

#[derive(Subcommand)]
pub enum AdminCommand {
    #[command(subcommand)]
    Keys(KeysCommand),
    #[command(subcommand)]
    Storage(StorageCommand),
    #[command(subcommand)]
    Users(UsersCommand),
    #[command(subcommand)]
    Tokens(TokensCommand),
    #[command(subcommand)]
    Pair(PairCommand),
    #[command(subcommand)]
    Settings(SettingsCommand),
    Backup {
        directory: PathBuf,
    },
    Audit {
        #[arg(long)]
        account: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SettingsCommand {
    Show,
    Set {
        #[arg(long, value_enum)]
        registration: Option<RegistrationArg>,
        #[arg(long)]
        default_quota: Option<String>,
        #[arg(long, value_enum)]
        collector_default: Option<OnOff>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RegistrationArg {
    Request,
    Closed,
}

impl RegistrationArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Closed => "closed",
        }
    }
}

#[derive(Subcommand)]
pub enum StorageCommand {
    Check,
}

#[derive(Subcommand)]
pub enum KeysCommand {
    Check,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StateFilter {
    Unverified,
    Pending,
    Active,
    Suspended,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

impl OnOff {
    fn yes(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Subcommand)]
pub enum UsersCommand {
    Create {
        #[arg(long)]
        email: String,
        #[arg(long, value_enum, default_value = "user")]
        role: RoleArg,
        #[arg(long)]
        quota: Option<String>,
    },
    Invite {
        #[arg(long)]
        email: String,
        #[arg(long, value_enum, default_value = "user")]
        role: RoleArg,
        #[arg(long)]
        quota: Option<String>,
    },
    List {
        #[arg(long, value_enum)]
        state: Option<StateFilter>,
    },
    Show {
        account: String,
    },
    Approve {
        account: String,
        #[arg(long)]
        quota: Option<String>,
        #[arg(long)]
        collector: bool,
    },
    Deny {
        account: String,
    },
    Set(SetArgs),
    Suspend {
        account: String,
    },
    Resume {
        account: String,
    },
    #[command(subcommand)]
    Owner(OwnerCommand),
    #[command(name = "reset-2fa")]
    Reset2fa {
        account: String,
    },
    Delete {
        account: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    User,
    Admin,
    Owner,
}

impl RoleArg {
    fn role(self) -> Role {
        match self {
            Self::User => Role::User,
            Self::Admin => Role::Admin,
            Self::Owner => Role::Owner,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NonOwnerRole {
    User,
    Admin,
}

impl NonOwnerRole {
    fn role(self) -> Role {
        match self {
            Self::User => Role::User,
            Self::Admin => Role::Admin,
        }
    }
}

#[derive(Subcommand)]
pub enum OwnerCommand {
    Grant {
        account: String,
    },
    Revoke {
        account: String,
        #[arg(long, value_enum, default_value = "admin")]
        to: NonOwnerRole,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
pub struct SetArgs {
    account: String,
    #[arg(long)]
    quota: Option<String>,
    #[arg(long, value_enum)]
    collector: Option<OnOff>,
    #[arg(long, value_enum)]
    sync: Option<OnOff>,
    #[arg(long)]
    yes: bool,
    #[arg(long, value_enum)]
    role: Option<NonOwnerRole>,
    #[arg(long)]
    max_vaults: Option<u32>,
}

#[derive(Subcommand)]
pub enum TokensCommand {
    Create {
        account: String,
        #[arg(long, default_value = "CLI token")]
        label: String,
        #[arg(long, value_delimiter = ',', default_value = "sync,collector,share")]
        scopes: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum PairCommand {
    Approve {
        user_code: String,
        account: String,
        #[arg(long, value_delimiter = ',')]
        scopes: Option<Vec<String>>,
    },
    Deny {
        user_code: String,
        account: String,
    },
}

type CliResult = Result<(), String>;

fn api_error(error: ApiErr) -> String {
    error.message
}

fn find(state: &AppState, who: &str) -> Result<AccountRow, String> {
    let registry = state.registry();
    let found = match who.parse::<AccountId>() {
        Ok(id) => registry.account(&id),
        Err(_) => registry.account_by_email(who),
    }
    .map_err(|e| e.to_string())?;
    found.ok_or_else(|| format!("no account matches {who}"))
}

fn quota_arg(value: &str) -> Result<Option<u64>, String> {
    let quota = parse_size(value)?;
    validate_quota(quota)?;
    Ok(quota)
}

fn parse_scopes(names: &[String]) -> Result<Vec<Scope>, String> {
    names
        .iter()
        .map(|name| match name.trim() {
            "sync" => Ok(Scope::Sync),
            "collector" => Ok(Scope::Collector),
            "share" => Ok(Scope::Share),
            "account" => Ok(Scope::Account),
            other => Err(format!("unknown scope {other}")),
        })
        .collect()
}

fn print_account(account: &AccountRow) {
    if JSON_OUTPUT.with(Cell::get) {
        println!(
            "{}",
            serde_json::json!({
                "accountId": account.account_id,
                "email": account.email,
                "state": account.state.as_str(),
                "role": account.role.as_str(),
                "syncAllowed": account.sync_allowed,
                "usageBytes": account.usage_bytes,
                "quotaBytes": account.quota_bytes,
                "maxVaults": account.max_vaults,
                "collectorAllowed": account.collector_allowed,
                "createdAt": account.created_at,
            })
        );
        return;
    }
    cli_println!(
        "{}  {}  state={}  role={}  sync={}  usage={} / {}  vaults<={}  collector={}  created={}",
        account.account_id,
        account.email,
        account.state.as_str(),
        account.role.as_str(),
        account.sync_allowed,
        format_size(Some(account.usage_bytes)),
        format_size(account.quota_bytes),
        account.max_vaults,
        account.collector_allowed,
        account.created_at,
    );
}

fn block_on<T>(future: impl std::future::Future<Output = T>) -> Result<T, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|runtime| runtime.block_on(future))
        .map_err(|e| e.to_string())
}

fn flush_deletions(state: &Shared) {
    match block_on(state.process_deletions()) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!(
            "note: some objects will be deleted later by the server ({})",
            error.message
        ),
        Err(error) => {
            eprintln!("note: some objects will be deleted later by the server ({error})")
        }
    }
}

fn storage_check(state: &Shared) -> CliResult {
    let health = block_on(state.objects.health())?.map_err(|e| e.to_string())?;
    cli_println!(
        "backend: {} ({})",
        health.backend,
        if health.ok {
            "reachable"
        } else {
            "NOT reachable"
        }
    );
    if let Some(detail) = &health.detail {
        cli_println!("detail: {detail}");
    }
    if !health.ok {
        return Err("storage backend is not reachable".into());
    }
    let probe_id: [u8; 16] = crate::util::random_bytes();
    let key = vrcx_0_nanashi_website_protocol::blob::object_key(
        "00000000000000000000000000000000",
        &data_encoding::HEXLOWER.encode(&probe_id),
    );
    let payload = crate::util::random_bytes::<64>().to_vec();
    block_on(async {
        state.objects.put(&key, payload.clone()).await?;
        let read = state.objects.get(&key).await?;
        state.objects.delete(&key).await?;
        Ok::<_, crate::objects::ObjectError>(read)
    })?
    .map_err(|e| e.to_string())
    .and_then(|read| {
        if read.as_deref() == Some(payload.as_slice()) {
            Ok(())
        } else {
            Err("read back different data".into())
        }
    })?;
    cli_println!("write / read / delete: ok");
    let mut missing = 0_u64;
    let mut checked = 0_u64;
    for account in state
        .registry()
        .list_accounts(None)
        .map_err(|e| e.to_string())?
    {
        if account.wrapped_adk.is_none() {
            continue;
        }
        let (store, keys) = state.open_store_with_keys(&account).map_err(api_error)?;
        let expected = store.all_object_ids().map_err(|e| e.to_string())?;
        let listed: std::collections::HashSet<String> =
            block_on(state.objects.list_all(&keys.prefix()))?
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|entry| entry.key)
                .collect();
        for object_id in expected {
            checked += 1;
            if !listed.contains(&keys.object_key(&object_id)) {
                missing += 1;
                eprintln!("missing object for a chunk of {}", account.account_id);
            }
        }
    }
    cli_println!("chunks checked: {checked}, missing objects: {missing}");
    let pending = state
        .registry()
        .pending_deletions()
        .map_err(|e| e.to_string())?;
    cli_println!("deletions waiting in the queue: {pending}");
    if missing > 0 {
        Err("some chunks have no object".into())
    } else {
        Ok(())
    }
}

fn settings(state: &Shared, command: SettingsCommand, now: i64) -> CliResult {
    match command {
        SettingsCommand::Show => {
            let registration = crate::routes::web::effective_registration(state);
            let registration = match registration {
                vrcx_0_nanashi_website_protocol::api::Registration::Request => "request",
                vrcx_0_nanashi_website_protocol::api::Registration::Closed => "closed",
            };
            cli_println!("registration: {registration}");
            cli_println!(
                "default quota: {}",
                format_size(crate::routes::web::effective_default_quota(state))
            );
            cli_println!(
                "collector default allowed: {}",
                crate::routes::web::effective_collector_default(state)
            );
        }
        SettingsCommand::Set {
            registration,
            default_quota,
            collector_default,
        } => {
            if registration.is_none() && default_quota.is_none() && collector_default.is_none() {
                return Err("set at least one setting".into());
            }
            let quota = default_quota.as_deref().map(quota_arg).transpose()?;
            let registry = state.registry();
            if let Some(registration) = registration {
                registry
                    .set_setting("registration", registration.as_str())
                    .map_err(|e| e.to_string())?;
            }
            if let Some(quota) = quota {
                registry
                    .set_setting("default_quota", &format_size(quota))
                    .map_err(|e| e.to_string())?;
            }
            if let Some(allowed) = collector_default {
                registry
                    .set_setting(
                        "collector_default_allowed",
                        if allowed.yes() { "true" } else { "false" },
                    )
                    .map_err(|e| e.to_string())?;
            }
            registry
                .audit(ACTOR, "settings-change", None, now)
                .map_err(|e| e.to_string())?;
            cli_println!("settings updated");
        }
    }
    Ok(())
}

fn backup(state: &Shared, directory: &std::path::Path, now: i64) -> CliResult {
    std::fs::create_dir(directory)
        .map_err(|error| format!("cannot create backup directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot secure backup directory: {error}"))?;
    }
    let account_dir = directory.join("accounts");
    std::fs::create_dir(&account_dir)
        .map_err(|error| format!("cannot create accounts backup directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&account_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot secure accounts backup directory: {error}"))?;
    }

    let accounts = {
        let registry = state.registry();
        let accounts = registry.list_accounts(None).map_err(|e| e.to_string())?;
        crate::db::backup_connection(
            registry.conn(),
            &directory.join("registry.db"),
            state.keys.registry_key(),
        )
        .map_err(|e| e.to_string())?;
        accounts
    };
    let mut copied = 0_usize;
    for account in accounts {
        if account.wrapped_adk.is_none() {
            continue;
        }
        let source =
            crate::db::account::account_db_path(&state.config.data_dir, &account.account_id);
        if !source.is_file() {
            continue;
        }
        let (store, keys) = state.open_store_with_keys(&account).map_err(api_error)?;
        let destination = account_dir.join(format!("{}.db", account.account_id));
        crate::db::backup_connection(store.connection(), &destination, keys.db_key())
            .map_err(|e| e.to_string())?;
        copied += 1;
    }
    state
        .registry()
        .audit(ACTOR, "backup", None, now)
        .map_err(|e| e.to_string())?;
    cli_println!(
        "backup written to {} ({} account databases)",
        directory.display(),
        copied
    );
    Ok(())
}

fn invite(
    state: &Shared,
    email: &str,
    role: RoleArg,
    quota: Option<String>,
    now: i64,
) -> CliResult {
    let email = email.trim().to_owned();
    if !email.contains('@') || email.len() > 254 || email.chars().any(char::is_whitespace) {
        return Err("invalid email".into());
    }
    let quota = quota
        .as_deref()
        .map(quota_arg)
        .transpose()?
        .unwrap_or_else(|| crate::routes::web::effective_default_quota(state));
    let account_id = AccountId::random().map_err(|error| error.to_string())?;
    let token = vrcx_0_nanashi_website_protocol::b64::encode(&crate::util::random_bytes::<32>());
    let token_hmac = state
        .keys
        .hmac(crate::routes::web::AUTH_TOKEN_PURPOSE, token.as_bytes());
    let collector_default = crate::routes::web::effective_collector_default(state);
    {
        let registry = state.registry();
        if registry
            .account_by_email(&email)
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("an account with that email already exists".into());
        }
        registry
            .create_account(&account_id, &email, AccountState::Unverified, quota, now)
            .map_err(|error| error.to_string())?;
        registry
            .set_collector_allowed(&account_id, collector_default)
            .map_err(|error| error.to_string())?;
        if role != RoleArg::User {
            registry
                .set_role(&account_id, role.role())
                .map_err(|error| error.to_string())?;
        }
        registry
            .insert_auth_token(
                &token_hmac,
                &account_id,
                "invite",
                now + (crate::routes::web::INVITE_TTL_MS / 1000),
                None,
            )
            .map_err(|error| error.to_string())?;
        registry
            .audit(ACTOR, "invite", Some(&account_id), now)
            .map_err(|error| error.to_string())?;
    }
    let origin = state
        .config
        .web_origins
        .first()
        .cloned()
        .unwrap_or_default();
    let link = format!("{origin}/invite#{token}");
    block_on(state.send_email(
        &email,
        crate::mail::invite(&link),
        format!("invite-{token}"),
    ))?
    .map_err(api_error)?;
    cli_println!("invited {email} as {} ({account_id})", role.role().as_str());
    Ok(())
}

#[cfg(test)]
pub fn run(state: &Shared, command: AdminCommand) -> CliResult {
    run_with_json(state, command, false)
}

pub fn run_with_json(state: &Shared, command: AdminCommand, json: bool) -> CliResult {
    JSON_OUTPUT.with(|mode| mode.set(json));
    let now = now_epoch();
    let result = (|| {
        match command {
            AdminCommand::Storage(StorageCommand::Check) => storage_check(state)?,
            AdminCommand::Keys(KeysCommand::Check) => {
                let accounts = state
                    .registry()
                    .list_accounts(None)
                    .map_err(|e| e.to_string())?;
                cli_println!(
                    "master key opens the registry ({} accounts)",
                    accounts.len()
                );
                cli_println!("server commit: {}", state.config.commit);
            }
            AdminCommand::Audit { account } => {
                let target = account.map(|who| find(state, &who)).transpose()?;
                for (actor, action, target, at) in state
                    .registry()
                    .audit_entries(target.as_ref().map(|a| &a.account_id))
                    .map_err(|e| e.to_string())?
                {
                    cli_println!("{at}  {actor}  {action}  {}", target.unwrap_or_default());
                }
            }
            AdminCommand::Settings(command) => settings(state, command, now)?,
            AdminCommand::Backup { directory } => backup(state, &directory, now)?,
            AdminCommand::Users(command) => users(state, command, now)?,
            AdminCommand::Tokens(TokensCommand::Create {
                account,
                label,
                scopes,
            }) => {
                let account = find(state, &account)?;
                let scopes = parse_scopes(&scopes)?;
                let token =
                    issue_api_token(state, &account, &label, &scopes, ClientKind::ManualToken)
                        .map_err(api_error)?;
                state
                    .registry()
                    .audit(ACTOR, "token-create", Some(&account.account_id), now)
                    .map_err(|e| e.to_string())?;
                cli_println!("{token}");
                eprintln!("Shown once. Store it in VRCX-0-Nanashi now.");
            }
            AdminCommand::Pair(PairCommand::Approve {
                user_code,
                account,
                scopes,
            }) => {
                let account = find(state, &account)?;
                let code = token::normalize_user_code(&user_code).map_err(|e| e.to_string())?;
                let registry = state.registry();
                let pairing = registry
                    .pairing_by_user_code(&code)
                    .map_err(|e| e.to_string())?
                    .filter(|p| p.expires_at > now)
                    .ok_or("no pending pairing with that code")?;
                let scopes = match scopes {
                    Some(names) => parse_scopes(&names)?,
                    None => pairing.requested_scopes.clone(),
                };
                if !registry
                    .decide_pairing(&code, &account.account_id, Some(&scopes))
                    .map_err(|e| e.to_string())?
                {
                    return Err("pairing already decided".into());
                }
                registry
                    .audit(ACTOR, "pair-approve", Some(&account.account_id), now)
                    .map_err(|e| e.to_string())?;
                cli_println!(
                    "approved {} ({}) for {}",
                    code,
                    pairing.device_label,
                    account.account_id
                );
            }
            AdminCommand::Pair(PairCommand::Deny { user_code, account }) => {
                let account = find(state, &account)?;
                let code = token::normalize_user_code(&user_code).map_err(|e| e.to_string())?;
                if !state
                    .registry()
                    .decide_pairing(&code, &account.account_id, None)
                    .map_err(|e| e.to_string())?
                {
                    return Err("no pending pairing with that code".into());
                }
                cli_println!("denied {code}");
            }
        }
        Ok(())
    })();
    JSON_OUTPUT.with(|mode| mode.set(false));
    result
}

fn users(state: &Shared, command: UsersCommand, now: i64) -> CliResult {
    match command {
        UsersCommand::Create { email, role, quota } => {
            let email = email.trim().to_owned();
            if !email.contains('@') || email.len() > 254 {
                return Err("invalid email".into());
            }
            let quota = match quota {
                Some(q) => quota_arg(&q)?,
                None => crate::routes::web::effective_default_quota(state),
            };
            let id = AccountId::random().map_err(|e| e.to_string())?;
            let registry = state.registry();
            registry
                .create_account(&id, &email, AccountState::Active, quota, now)
                .map_err(|e| e.to_string())?;
            registry
                .set_collector_allowed(&id, crate::routes::web::effective_collector_default(state))
                .map_err(|e| e.to_string())?;
            if role != RoleArg::User {
                registry
                    .set_role(&id, role.role())
                    .map_err(|e| e.to_string())?;
            }
            registry
                .audit(ACTOR, "account-create", Some(&id), now)
                .map_err(|e| e.to_string())?;
            cli_println!("{id}");
        }
        UsersCommand::Invite { email, role, quota } => invite(state, &email, role, quota, now)?,
        UsersCommand::List { state: filter } => {
            let filter = filter.map(|f| match f {
                StateFilter::Unverified => AccountState::Unverified,
                StateFilter::Pending => AccountState::Pending,
                StateFilter::Active => AccountState::Active,
                StateFilter::Suspended => AccountState::Suspended,
            });
            for account in state
                .registry()
                .list_accounts(filter)
                .map_err(|e| e.to_string())?
            {
                print_account(&account);
            }
        }
        UsersCommand::Show { account } => {
            let account = find(state, &account)?;
            print_account(&account);
            if !account.signup_message.is_empty() {
                cli_println!("message: {}", account.signup_message);
            }
        }
        UsersCommand::Approve {
            account,
            quota,
            collector,
        } => {
            let account = find(state, &account)?;
            if account.state != AccountState::Pending {
                return Err(format!(
                    "account is {}, not pending",
                    account.state.as_str()
                ));
            }
            let registry_quota = match quota {
                Some(q) => Some(quota_arg(&q)?),
                None => None,
            };
            {
                let registry = state.registry();
                if let Some(q) = registry_quota {
                    registry
                        .set_quota(&account.account_id, q)
                        .map_err(|e| e.to_string())?;
                }
                if collector {
                    registry
                        .set_collector_allowed(&account.account_id, true)
                        .map_err(|e| e.to_string())?;
                }
            }
            state
                .approve_account(&account.account_id, ACTOR)
                .map_err(api_error)?;
            cli_println!("approved {}", account.account_id);
        }
        UsersCommand::Deny { account } => {
            let account = find(state, &account)?;
            if account.state != AccountState::Pending {
                return Err(format!(
                    "account is {}, not pending",
                    account.state.as_str()
                ));
            }
            state
                .delete_account(&account.account_id)
                .map_err(api_error)?;
            cli_println!("denied and deleted {}", account.account_id);
        }
        UsersCommand::Set(args) => {
            let account = find(state, &args.account)?;
            let mut registry = state.registry();
            let id = &account.account_id;
            if let Some(q) = &args.quota {
                registry
                    .set_quota(id, quota_arg(q)?)
                    .map_err(|e| e.to_string())?;
                registry
                    .audit(ACTOR, "set-quota", Some(id), now)
                    .map_err(|e| e.to_string())?;
            }
            if let Some(c) = args.collector {
                registry
                    .set_collector_allowed(id, c.yes())
                    .map_err(|e| e.to_string())?;
                registry
                    .audit(ACTOR, "set-collector", Some(id), now)
                    .map_err(|e| e.to_string())?;
            }
            if let Some(sync) = args.sync {
                if sync.yes() {
                    drop(registry);
                    state.allow_sync(id, ACTOR).map_err(api_error)?;
                    registry = state.registry();
                } else {
                    if !args.yes {
                        return Err(format!(
                            "this purges all synced data of {} permanently; repeat with --yes",
                            account.account_id
                        ));
                    }
                    drop(registry);
                    state.forbid_sync(id, ACTOR).map_err(api_error)?;
                    flush_deletions(state);
                    registry = state.registry();
                }
            }
            if let Some(role) = args.role {
                if account.is_owner() {
                    return Err("this account is an owner; use `users owner revoke` first".into());
                }
                registry
                    .set_role(id, role.role())
                    .map_err(|e| e.to_string())?;
                registry
                    .audit(ACTOR, "set-role", Some(id), now)
                    .map_err(|e| e.to_string())?;
            }
            if let Some(v) = args.max_vaults {
                if !(1..=1000).contains(&v) {
                    return Err("max vaults must be 1 to 1000".into());
                }
                registry.set_max_vaults(id, v).map_err(|e| e.to_string())?;
            }
            drop(registry);
            print_account(&find(state, id.as_str())?);
        }
        UsersCommand::Suspend { account } => {
            let account = find(state, &account)?;
            if account.state != AccountState::Active {
                return Err(format!("account is {}, not active", account.state.as_str()));
            }
            let registry = state.registry();
            registry
                .set_state(&account.account_id, AccountState::Suspended)
                .map_err(|e| e.to_string())?;
            registry
                .audit(ACTOR, "suspend", Some(&account.account_id), now)
                .map_err(|e| e.to_string())?;
            cli_println!("suspended {}", account.account_id);
        }
        UsersCommand::Resume { account } => {
            let account = find(state, &account)?;
            if account.state != AccountState::Suspended {
                return Err(format!(
                    "account is {}, not suspended",
                    account.state.as_str()
                ));
            }
            let registry = state.registry();
            registry
                .set_state(&account.account_id, AccountState::Active)
                .map_err(|e| e.to_string())?;
            registry
                .audit(ACTOR, "resume", Some(&account.account_id), now)
                .map_err(|e| e.to_string())?;
            cli_println!("resumed {}", account.account_id);
        }
        UsersCommand::Owner(OwnerCommand::Grant { account }) => {
            let account = find(state, &account)?;
            let registry = state.registry();
            registry
                .set_role(&account.account_id, Role::Owner)
                .map_err(|e| e.to_string())?;
            registry
                .audit(ACTOR, "owner-grant", Some(&account.account_id), now)
                .map_err(|e| e.to_string())?;
            cli_println!("{} is now an owner", account.account_id);
        }
        UsersCommand::Owner(OwnerCommand::Revoke { account, to, force }) => {
            let account = find(state, &account)?;
            if !account.is_owner() {
                return Err(format!("{} is not an owner", account.account_id));
            }
            let registry = state.registry();
            if !force
                && registry
                    .role_count(Role::Owner)
                    .map_err(|e| e.to_string())?
                    <= 1
            {
                return Err("this is the last owner; repeat with --force to remove it".into());
            }
            registry
                .set_role(&account.account_id, to.role())
                .map_err(|e| e.to_string())?;
            registry
                .audit(ACTOR, "owner-revoke", Some(&account.account_id), now)
                .map_err(|e| e.to_string())?;
            cli_println!("{} is now {}", account.account_id, to.role().as_str());
        }
        UsersCommand::Reset2fa { account } => {
            let account = find(state, &account)?;
            let registry = state.registry();
            registry
                .reset_twofa(&account.account_id)
                .map_err(|e| e.to_string())?;
            registry
                .audit(ACTOR, "reset-2fa", Some(&account.account_id), now)
                .map_err(|e| e.to_string())?;
            cli_println!(
                "2FA reset for {}; the user must enroll again at next sign-in",
                account.account_id
            );
        }
        UsersCommand::Delete { account, yes } => {
            let account = find(state, &account)?;
            if !yes {
                return Err(format!(
                    "this deletes {} and all its data permanently; repeat with --yes",
                    account.account_id
                ));
            }
            state
                .delete_account(&account.account_id)
                .map_err(api_error)?;
            cli_println!("deleted {}", account.account_id);
        }
    }
    Ok(())
}
