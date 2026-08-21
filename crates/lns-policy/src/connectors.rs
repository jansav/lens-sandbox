use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::providers::InjectionDef;
use crate::{HttpRule, NetworkPolicy, RouteRule, Scheme, Transport, Verdict, is_false};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Credential,
    Oauth,
}

/// A route a connector needs reachable. Verdict is implicitly `allow`; `transport` defaults to direct. Materializes into a full [`RouteRule`] at run time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorRoute {
    #[serde(rename = "match")]
    pub match_pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_terminate: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HttpRule>,
}

impl ConnectorRoute {
    /// HTTP-level `rules` can only be enforced when the proxy terminates TLS, so declaring them implies termination.
    pub fn to_route_rule(&self) -> RouteRule {
        RouteRule {
            match_pattern: self.match_pattern.clone(),
            verdict: Verdict::Allow,
            transport: self.transport.unwrap_or(Transport::Direct),
            scheme: self.scheme,
            description: None,
            tls_terminate: self.tls_terminate || !self.rules.is_empty(),
            rules: self.rules.clone(),
            binaries: None,
        }
    }
}

pub use lns_spec::Credential as CredentialAuth;

/// Which interactive sign-in an `oauth` connector uses: the RFC 8628 device flow (default) or the browser-redirect authorization-code + PKCE flow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OauthFlow {
    #[default]
    Device,
    Pkce,
}

impl OauthFlow {
    fn is_device(&self) -> bool {
        matches!(self, OauthFlow::Device)
    }
}

/// Interactive sign-in configuration for an `oauth` connector: `flow` selects device (RFC 8628) or pkce, alongside the same env/placeholder/injection wiring a credential carries; `clientId` is optional (community builds ship none and fall back to a pasted token), with `deviceAuthorizationEndpoint` required for device and `authorizationEndpoint` for pkce; `clientSecret` is set only for confidential device clients (e.g. Google) that require it in the token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthAuth {
    #[serde(default, skip_serializing_if = "OauthFlow::is_device")]
    pub flow: OauthFlow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_field: Option<String>,
    pub env_var: String,
    pub placeholder: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub injections: Vec<InjectionDef>,
}

/// An offer-time fallback letting the user paste a token into the connector's existing credential slot when the primary auth (e.g. an oauth device flow) is blocked; `help` is an optional URL for creating one and `command` an optional host CLI that mints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenFallback {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connector {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub auth_kind: AuthKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<ConnectorRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OauthAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fallback: Option<TokenFallback>,
}

impl OauthAuth {
    /// The client id a sign-in can use, with any `${VAR}` resolved; `None` when it names nothing, so the flow is withheld rather than attempted with a literal reference.
    pub fn client_id_resolved(&self) -> Option<String> {
        resolved_env_value(self.client_id.as_deref())
    }

    /// The client secret a confidential device client sends, with any `${VAR}` resolved.
    pub fn client_secret_resolved(&self) -> Option<String> {
        resolved_env_value(self.client_secret.as_deref())
    }
}

fn resolved_env_value(raw: Option<&str>) -> Option<String> {
    let resolved = crate::env_subst::resolve_from_env(raw?);
    if resolved.is_empty() || resolved.contains("${") {
        return None;
    }
    Some(resolved)
}

impl Connector {
    /// The user-facing label for cards and prompts; falls back to the id when no `name` is set.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }

    /// Each authKind must carry its matching block, an oauth block must carry the endpoint its `flow` needs, and the id and placeholder obey the grammar every keyspace and the boundary depend on.
    pub fn validate(&self) -> Result<(), String> {
        if !lns_spec::is_legal_connector_id(&self.id) {
            return Err(format!(
                "invalid connector id {:?}: an id is one lowercase DNS label, which is what keeps it out of the keyspace a declared credential answers under",
                self.id
            ));
        }
        self.validate_placeholders()?;
        match self.auth_kind {
            AuthKind::Credential if self.credential.is_none() => Err(format!(
                "connector {:?} declares authKind credential but has no `credential:` block",
                self.id
            )),
            AuthKind::Oauth => self.validate_oauth(),
            _ => Ok(()),
        }
    }

    fn validate_placeholders(&self) -> Result<(), String> {
        for placeholder in self
            .credential
            .iter()
            .map(|c| &c.placeholder)
            .chain(self.oauth.iter().map(|o| &o.placeholder))
        {
            lns_spec::credential::validate_placeholder(placeholder, &self.id)?;
        }
        Ok(())
    }

    fn validate_oauth(&self) -> Result<(), String> {
        let Some(oauth) = self.oauth.as_ref() else {
            return Err(format!(
                "connector {:?} declares authKind oauth but has no `oauth:` block",
                self.id
            ));
        };
        match oauth.flow {
            OauthFlow::Device if oauth.device_authorization_endpoint.is_none() => Err(format!(
                "connector {:?} uses the oauth device flow but has no `deviceAuthorizationEndpoint`",
                self.id
            )),
            OauthFlow::Pkce if oauth.authorization_endpoint.is_none() => Err(format!(
                "connector {:?} uses the oauth pkce flow but has no `authorizationEndpoint`",
                self.id
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    #[serde(default)]
    pub connectors: Vec<Connector>,
}

impl Catalog {
    fn validate(&self) -> Result<(), String> {
        for i in &self.connectors {
            i.validate()?;
        }
        NetworkPolicy {
            egress: crate::Egress {
                http: self
                    .connectors
                    .iter()
                    .flat_map(|connector| {
                        connector.routes.iter().map(ConnectorRoute::to_route_rule)
                    })
                    .collect(),
                ..crate::Egress::default()
            },
        }
        .validate_local_transport()
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn load_or_default(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let catalog: Catalog = serde_yaml::from_str(&text)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                catalog
                    .validate()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(catalog)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        crate::secure_file::write_yaml_document_atomic(path, yaml.as_bytes())
    }
}

pub fn default_connectors_path() -> PathBuf {
    lns_spec::lns_home().join("connectors.yaml")
}

pub trait CatalogStore: Send + Sync {
    fn save(&self, catalog: &Catalog) -> io::Result<()>;
}

pub struct FileCatalogStore {
    pub path: PathBuf,
}

impl FileCatalogStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl CatalogStore for FileCatalogStore {
    fn save(&self, catalog: &Catalog) -> io::Result<()> {
        catalog.save_atomic(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::InjectionKind;

    fn credential(env_var: &str, placeholder: &str, domain: &str) -> CredentialAuth {
        CredentialAuth {
            env_var: env_var.into(),
            placeholder: placeholder.into(),
            injections: vec![InjectionDef {
                kind: InjectionKind::BearerHeader,
                domain: domain.into(),
                header: None,
            }],
        }
    }

    fn oauth_auth(env_var: &str, placeholder: &str, domain: &str) -> OauthAuth {
        OauthAuth {
            flow: OauthFlow::Device,
            client_id: Some("Iv1.example0000".into()),
            client_secret: None,
            scopes: vec!["repo".into()],
            device_authorization_endpoint: Some("https://example.com/login/device/code".into()),
            authorization_endpoint: None,
            token_endpoint: "https://example.com/login/oauth/access_token".into(),
            userinfo_endpoint: Some("https://example.com/user".into()),
            account_field: Some("login".into()),
            env_var: env_var.into(),
            placeholder: placeholder.into(),
            injections: vec![InjectionDef {
                kind: InjectionKind::BearerHeader,
                domain: domain.into(),
                header: None,
            }],
        }
    }

    fn pkce_oauth_auth(env_var: &str, placeholder: &str, domain: &str) -> OauthAuth {
        OauthAuth {
            flow: OauthFlow::Pkce,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            device_authorization_endpoint: None,
            authorization_endpoint: Some("https://example.com/auth".into()),
            token_endpoint: "https://example.com/api/v1/auth/keys".into(),
            userinfo_endpoint: None,
            account_field: None,
            env_var: env_var.into(),
            placeholder: placeholder.into(),
            injections: vec![InjectionDef {
                kind: InjectionKind::BearerHeader,
                domain: domain.into(),
                header: None,
            }],
        }
    }

    fn pkce_connector() -> Connector {
        Connector {
            id: "examplepkce".into(),
            name: None,
            auth_kind: AuthKind::Oauth,
            routes: vec![route("api.examplepkce.com")],
            credential: None,
            oauth: Some(pkce_oauth_auth(
                "EXAMPLEPKCE_TOKEN",
                "examplepkce_LNSPLACEHOLDER0000",
                "api.examplepkce.com",
            )),
            token_fallback: None,
        }
    }

    fn route(host: &str) -> ConnectorRoute {
        ConnectorRoute {
            match_pattern: host.into(),
            transport: None,
            scheme: None,
            tls_terminate: false,
            rules: Vec::new(),
        }
    }

    fn sample_connector() -> Connector {
        Connector {
            id: "acme".into(),
            name: None,
            auth_kind: AuthKind::Credential,
            routes: vec![route("api.acme.corp")],
            credential: Some(credential(
                "ACME_API_KEY",
                "acme_LNSPLACEHOLDER0000",
                "api.acme.corp",
            )),
            oauth: None,
            token_fallback: None,
        }
    }

    fn oauth_connector() -> Connector {
        Connector {
            id: "examplehub".into(),
            name: None,
            auth_kind: AuthKind::Oauth,
            routes: vec![route("api.examplehub.com")],
            credential: None,
            oauth: Some(oauth_auth(
                "EXAMPLEHUB_TOKEN",
                "examplehub_LNSPLACEHOLDER0000",
                "api.examplehub.com",
            )),
            token_fallback: None,
        }
    }

    #[test]
    fn a_simple_connector_route_round_trips_as_just_a_match() {
        let r = route("gitlab.com");
        let yaml = serde_yaml::to_string(&r).unwrap();
        assert!(yaml.contains("match: gitlab.com"), "got: {yaml}");
        assert!(
            !yaml.contains("verdict")
                && !yaml.contains("transport")
                && !yaml.contains("tlsTerminate"),
            "a bare route must stay minimal: {yaml}"
        );
        let parsed: ConnectorRoute = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn a_least_privilege_connector_route_round_trips_with_scheme_and_http_rules() {
        let r = ConnectorRoute {
            match_pattern: "gitlab.com".into(),
            transport: None,
            scheme: Some(Scheme::Https),
            tls_terminate: false,
            rules: vec![HttpRule {
                method: Some("GET".into()),
                path: Some("/api/v4/**".into()),
            }],
        };
        let yaml = serde_yaml::to_string(&r).unwrap();
        assert!(yaml.contains("scheme: https"), "got: {yaml}");
        assert!(yaml.contains("path: /api/v4/**"), "got: {yaml}");
        let parsed: ConnectorRoute = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn to_route_rule_grants_allow_and_defaults_transport_to_direct() {
        let rr = route("gitlab.com").to_route_rule();
        assert_eq!(rr.match_pattern, "gitlab.com");
        assert_eq!(rr.verdict, Verdict::Allow);
        assert_eq!(rr.transport, Transport::Direct);
        assert!(!rr.tls_terminate);
        assert!(rr.rules.is_empty());
    }

    #[test]
    fn to_route_rule_honours_an_explicit_transport() {
        let mut r = route("gitlab.com");
        r.transport = Some(Transport::Upstream);
        assert_eq!(r.to_route_rule().transport, Transport::Upstream);
    }

    #[test]
    fn to_route_rule_implies_tls_termination_when_http_rules_are_present() {
        let r = ConnectorRoute {
            match_pattern: "gitlab.com".into(),
            transport: None,
            scheme: Some(Scheme::Https),
            tls_terminate: false,
            rules: vec![HttpRule {
                method: Some("GET".into()),
                path: None,
            }],
        };
        let rr = r.to_route_rule();
        assert!(
            rr.tls_terminate,
            "HTTP-level rules can't be enforced without terminating TLS"
        );
        assert_eq!(rr.scheme, Some(Scheme::Https));
        assert_eq!(rr.rules.len(), 1);
    }

    #[test]
    fn auth_kind_serializes_in_snake_case() {
        assert_eq!(
            serde_yaml::to_string(&AuthKind::Credential).unwrap().trim(),
            "credential"
        );
        assert_eq!(
            serde_yaml::to_string(&AuthKind::Oauth).unwrap().trim(),
            "oauth"
        );
    }

    #[test]
    fn oauth_flow_serializes_in_snake_case() {
        assert_eq!(
            serde_yaml::to_string(&OauthFlow::Device).unwrap().trim(),
            "device"
        );
        assert_eq!(
            serde_yaml::to_string(&OauthFlow::Pkce).unwrap().trim(),
            "pkce"
        );
    }

    #[test]
    fn credential_connector_round_trips_with_a_named_credential_block() {
        let i = sample_connector();
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(yaml.contains("authKind: credential"), "got: {yaml}");
        assert!(yaml.contains("credential:"), "got: {yaml}");
        assert!(yaml.contains("envVar: ACME_API_KEY"), "got: {yaml}");
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn an_oauth_connector_round_trips_with_an_oauth_block_and_no_credential_block() {
        let i = oauth_connector();
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(yaml.contains("authKind: oauth"), "got: {yaml}");
        assert!(yaml.contains("oauth:"), "got: {yaml}");
        assert!(yaml.contains("clientId:"), "got: {yaml}");
        assert!(yaml.contains("deviceAuthorizationEndpoint:"), "got: {yaml}");
        assert!(
            !yaml.contains("credential:"),
            "an oauth entry must not carry a credential block: {yaml}"
        );
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn an_oauth_connector_round_trips_an_optional_client_secret() {
        let mut i = oauth_connector();
        i.oauth.as_mut().unwrap().client_secret = Some("some-client-secret".into());
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(
            yaml.contains("clientSecret: some-client-secret"),
            "got: {yaml}"
        );
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn an_oauth_connector_without_a_client_secret_omits_it_from_yaml() {
        let yaml = serde_yaml::to_string(&oauth_connector()).unwrap();
        assert!(
            !yaml.contains("clientSecret"),
            "a public-client oauth entry must not serialize an empty client secret: {yaml}"
        );
    }

    #[test]
    fn display_name_prefers_an_explicit_name_and_falls_back_to_id() {
        let mut i = sample_connector();
        assert_eq!(
            i.display_name(),
            "acme",
            "an absent name falls back to the id"
        );
        i.name = Some("Acme Corp".into());
        assert_eq!(i.display_name(), "Acme Corp");
    }

    #[test]
    fn an_connector_round_trips_its_optional_display_name() {
        let mut i = oauth_connector();
        i.name = Some("ExampleHub".into());
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(yaml.contains("name: ExampleHub"), "got: {yaml}");
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn an_connector_without_a_name_omits_it_from_yaml() {
        let yaml = serde_yaml::to_string(&sample_connector()).unwrap();
        assert!(
            !yaml.contains("name:"),
            "an absent name must not serialize: {yaml}"
        );
    }

    #[test]
    fn an_connector_round_trips_its_optional_token_fallback_with_a_help_url() {
        let mut i = oauth_connector();
        i.token_fallback = Some(TokenFallback {
            help: Some("https://example.com/tokens/new".into()),
            command: None,
        });
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(yaml.contains("tokenFallback:"), "got: {yaml}");
        assert!(
            yaml.contains("help: https://example.com/tokens/new"),
            "got: {yaml}"
        );
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn a_token_fallback_round_trips_with_no_help() {
        let mut i = oauth_connector();
        i.token_fallback = Some(TokenFallback {
            help: None,
            command: None,
        });
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(yaml.contains("tokenFallback:"), "got: {yaml}");
        assert!(
            !yaml.contains("help:"),
            "an absent help must not serialize: {yaml}"
        );
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn an_connector_without_a_token_fallback_omits_it_from_yaml() {
        let yaml = serde_yaml::to_string(&oauth_connector()).unwrap();
        assert!(
            !yaml.contains("tokenFallback"),
            "an absent token fallback must not serialize: {yaml}"
        );
    }

    #[test]
    fn validate_rejects_a_credential_connector_missing_its_block() {
        let bad = Connector {
            id: "x".into(),
            name: None,
            auth_kind: AuthKind::Credential,
            routes: Vec::new(),
            credential: None,
            oauth: None,
            token_fallback: None,
        };
        let err = bad.validate().unwrap_err();
        assert!(err.contains("credential"), "got: {err}");
    }

    #[test]
    fn validate_accepts_a_well_formed_credential_connector() {
        assert!(sample_connector().validate().is_ok());
    }

    #[test]
    fn validate_rejects_an_oauth_connector_missing_its_block() {
        let bad = Connector {
            id: "x".into(),
            name: None,
            auth_kind: AuthKind::Oauth,
            routes: Vec::new(),
            credential: None,
            oauth: None,
            token_fallback: None,
        };
        let err = bad.validate().unwrap_err();
        assert!(err.contains("oauth"), "got: {err}");
    }

    #[test]
    fn validate_accepts_a_well_formed_oauth_connector() {
        assert!(oauth_connector().validate().is_ok());
    }

    #[test]
    fn an_oauth_block_defaults_to_the_device_flow_and_omits_it_from_yaml() {
        let yaml = serde_yaml::to_string(&oauth_connector()).unwrap();
        assert!(
            !yaml.contains("flow:"),
            "the default device flow must not serialize: {yaml}"
        );
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.oauth.unwrap().flow, OauthFlow::Device);
    }

    #[test]
    fn a_pkce_oauth_connector_round_trips_with_flow_and_an_authorization_endpoint_and_no_client_id()
    {
        let i = pkce_connector();
        let yaml = serde_yaml::to_string(&i).unwrap();
        assert!(yaml.contains("flow: pkce"), "got: {yaml}");
        assert!(
            yaml.contains("authorizationEndpoint: https://example.com/auth"),
            "got: {yaml}"
        );
        assert!(
            !yaml.contains("clientId:"),
            "a pkce entry needs no client id: {yaml}"
        );
        assert!(
            !yaml.contains("deviceAuthorizationEndpoint:"),
            "a pkce entry has no device endpoint: {yaml}"
        );
        let parsed: Connector = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, i);
    }

    #[test]
    fn validate_accepts_a_pkce_oauth_connector_without_a_client_id() {
        assert!(pkce_connector().validate().is_ok());
    }

    #[test]
    fn validate_rejects_a_pkce_oauth_connector_missing_its_authorization_endpoint() {
        let mut i = pkce_connector();
        i.oauth.as_mut().unwrap().authorization_endpoint = None;
        let err = i.validate().unwrap_err();
        assert!(err.contains("authorizationEndpoint"), "got: {err}");
    }

    #[test]
    fn validate_rejects_a_device_oauth_connector_missing_its_device_authorization_endpoint() {
        let mut i = oauth_connector();
        i.oauth.as_mut().unwrap().device_authorization_endpoint = None;
        let err = i.validate().unwrap_err();
        assert!(err.contains("deviceAuthorizationEndpoint"), "got: {err}");
    }

    #[test]
    fn catalog_round_trips_and_empty_connectors_is_the_default() {
        let empty: Catalog = serde_yaml::from_str("{}").unwrap();
        assert!(empty.connectors.is_empty());
        let c = Catalog {
            connectors: vec![sample_connector()],
        };
        let parsed: Catalog = serde_yaml::from_str(&serde_yaml::to_string(&c).unwrap()).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    #[serial_test::serial(env)]
    fn a_client_id_reference_resolves_from_the_environment() {
        use crate::test_env::EnvVarGuard;
        let _g = EnvVarGuard::set("LNS_TEST_OAUTH_CLIENT_ID", "resolved-client");
        let mut c = oauth_connector();
        c.oauth.as_mut().unwrap().client_id = Some("${LNS_TEST_OAUTH_CLIENT_ID}".into());
        assert_eq!(
            c.oauth.unwrap().client_id_resolved().as_deref(),
            Some("resolved-client"),
            "a real client id lives in the environment, never in the document"
        );
    }

    #[test]
    #[serial_test::serial(env)]
    fn an_unset_client_id_reference_resolves_to_no_usable_id() {
        use crate::test_env::EnvVarGuard;
        let _g = EnvVarGuard::unset("LNS_TEST_ABSENT_CLIENT_ID");
        let mut c = oauth_connector();
        c.oauth.as_mut().unwrap().client_id = Some("${LNS_TEST_ABSENT_CLIENT_ID}".into());
        assert!(
            c.oauth.unwrap().client_id_resolved().is_none(),
            "a build that ships no client id must withhold the flow, not attempt it with a literal reference"
        );
    }

    #[test]
    #[serial_test::serial(env)]
    fn reading_a_catalog_leaves_a_client_id_reference_in_the_document() {
        use crate::test_env::EnvVarGuard;
        let _g = EnvVarGuard::set("LNS_TEST_OAUTH_CLIENT_ID", "resolved-client");
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("connectors.yaml");
        let mut c = oauth_connector();
        c.oauth.as_mut().unwrap().client_id = Some("${LNS_TEST_OAUTH_CLIENT_ID}".into());
        Catalog {
            connectors: vec![c],
        }
        .save_atomic(&path)
        .unwrap();

        let read = Catalog::load_or_default(&path).unwrap();
        read.save_atomic(&path).unwrap();

        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("${LNS_TEST_OAUTH_CLIENT_ID}"),
            "a read-modify-write of the catalog must not bake the resolved id into the file, which is how a real client id would end up committed"
        );
    }

    #[test]
    fn load_or_default_returns_empty_when_file_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let c = Catalog::load_or_default(&dir.path().join("nope.yaml")).unwrap();
        assert_eq!(c, Catalog::default());
    }

    #[test]
    fn load_or_default_reads_an_existing_user_catalog() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".lns/connectors.yaml");
        Catalog {
            connectors: vec![sample_connector()],
        }
        .save_atomic(&path)
        .unwrap();
        let c = Catalog::load_or_default(&path).unwrap();
        assert_eq!(c.connectors.len(), 1);
        assert_eq!(c.connectors[0].id, "acme");
    }

    #[test]
    fn load_or_default_rejects_an_upstream_route_transport() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".lns/connectors.yaml");
        let mut connector = sample_connector();
        connector.routes[0].transport = Some(Transport::Upstream);
        Catalog {
            connectors: vec![connector],
        }
        .save_atomic(&path)
        .unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("upstream transport isn't supported in the local sandbox"),
            "got: {err}"
        );
    }

    #[test]
    fn load_or_default_surfaces_non_not_found_io_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("is-a-dir");
        fs::create_dir(&path).unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn load_or_default_surfaces_invalid_yaml_as_io_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("broken.yaml");
        fs::write(&path, "connectors: not-a-list\n").unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn load_or_default_rejects_an_inconsistent_credential_entry_as_invalid_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("inconsistent.yaml");
        fs::write(&path, "connectors:\n  - id: x\n    authKind: credential\n").unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn load_or_default_rejects_an_id_that_reaches_another_keyspace() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("colliding.yaml");
        fs::write(
            &path,
            "connectors:\n  - id: \"env:SOME_TOKEN\"\n    authKind: credential\n    credential:\n      envVar: SOME_TOKEN\n      placeholder: some_LNSPLACEHOLDER0000\n",
        )
        .unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "a declaration nothing supplies answers under env:<var>, so an entry spelling one would take over that value; got: {err}"
        );
    }

    #[test]
    fn load_or_default_rejects_a_placeholder_a_stream_could_carry_by_accident() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("short.yaml");
        fs::write(
            &path,
            "connectors:\n  - id: some-provider\n    authKind: credential\n    credential:\n      envVar: SOME_TOKEN\n      placeholder: lns-short\n",
        )
        .unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "the boundary substitutes this marker by substring in outbound bytes, whichever document declared it; got: {err}"
        );
    }

    #[test]
    fn load_or_default_rejects_a_placeholder_a_real_token_could_pass_for() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("real-looking.yaml");
        fs::write(
            &path,
            "connectors:\n  - id: some-provider\n    authKind: credential\n    credential:\n      envVar: SOME_TOKEN\n      placeholder: sk-live-0123456789\n",
        )
        .unwrap();
        let err = Catalog::load_or_default(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got: {err}");
    }

    #[test]
    fn save_atomic_round_trips_creates_parent_and_leaves_no_tmp() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested/dir/.lns/connectors.yaml");
        let c = Catalog {
            connectors: vec![sample_connector()],
        };
        c.save_atomic(&path).unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("yaml.tmp").exists());
        assert_eq!(Catalog::load_or_default(&path).unwrap(), c);
    }

    #[test]
    fn save_atomic_does_not_follow_a_symlink_planted_at_the_tmp_path() {
        // This catalog declares where a credential is injected, so a write redirected out of it is a write of whatever the symlink names.
        let dir = tempfile::TempDir::new().unwrap();
        let victim = dir.path().join("victim");
        let victim_contents = b"victim-data-must-survive";
        fs::write(&victim, victim_contents).unwrap();
        let path = dir.path().join(".lns/connectors.yaml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("yaml.tmp")).unwrap();

        let _ = Catalog {
            connectors: vec![sample_connector()],
        }
        .save_atomic(&path);

        assert_eq!(
            fs::read(&victim).unwrap(),
            victim_contents,
            "a symlink at the tmp path must not redirect the catalog write"
        );
    }

    #[test]
    fn file_catalog_store_save_writes_yaml_readable_by_load_or_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".lns/connectors.yaml");
        let store = FileCatalogStore::new(path.clone());
        let c = Catalog {
            connectors: vec![sample_connector()],
        };
        store.save(&c).unwrap();
        assert_eq!(Catalog::load_or_default(&path).unwrap(), c);
    }

    #[test]
    fn file_catalog_store_save_to_unwritable_parent_surfaces_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let not_a_dir = dir.path().join("file");
        fs::write(&not_a_dir, b"").unwrap();
        let store = FileCatalogStore::new(not_a_dir.join("nested/.lns/connectors.yaml"));
        let err = store.save(&Catalog::default()).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    #[serial_test::serial(env)]
    fn default_connectors_path_names_a_file_inside_the_lns_home() {
        use crate::test_env::EnvVarGuard;
        let _g1 = EnvVarGuard::unset("LNS_HOME");
        let _g2 = EnvVarGuard::set("HOME", "/home/dev");
        assert_eq!(
            default_connectors_path(),
            PathBuf::from("/home/dev/.lns/connectors.yaml")
        );
    }

    #[test]
    #[serial_test::serial(env)]
    fn default_connectors_path_follows_the_lns_home_override() {
        use crate::test_env::EnvVarGuard;
        let _g1 = EnvVarGuard::set("LNS_HOME", "/srv/lns-state");
        let _g2 = EnvVarGuard::set("HOME", "/home/should-be-ignored");
        assert_eq!(
            default_connectors_path(),
            PathBuf::from("/srv/lns-state/connectors.yaml"),
            "one variable moves every file lns keeps, so this one must not need its own"
        );
    }
}
