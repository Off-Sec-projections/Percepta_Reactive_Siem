use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::certificate_authority::CAService;
use crate::mtls_peer;
use percepta_server::percepta::{
    response_service_server::ResponseService as ResponseServiceTrait, CommandKind, ResponseCommand,
    ResponseResult, ResultStatus,
};

#[derive(Clone, Debug, serde::Serialize)]
pub struct CommandStatusView {
    pub command_id: String,
    pub target_agent_id: String,
    pub kind: i32,
    pub ip: String,
    pub username: String,
    pub duration_seconds: u32,
    pub custom_kind: String,
    pub args: std::collections::HashMap<String, String>,
    pub status: i32,
    pub message: String,
    pub issued_at_rfc3339: String,
    pub completed_at_rfc3339: Option<String>,
    pub artifact_name: Option<String>,
    pub has_artifact: bool,
}

#[derive(Clone)]
pub struct ResponseHubHandle(pub Arc<ResponseHub>);

impl ResponseHubHandle {
    pub fn new() -> Self {
        Self(Arc::new(ResponseHub::new()))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch(
        &self,
        target_agent_id: &str,
        kind: CommandKind,
        ip: Option<String>,
        username: Option<String>,
        duration_seconds: u32,
        args: std::collections::HashMap<String, String>,
        custom_kind: Option<String>,
    ) -> Result<String, Status> {
        self.0
            .dispatch(
                target_agent_id,
                kind,
                ip,
                username,
                duration_seconds,
                args,
                custom_kind,
            )
            .await
    }

    pub async fn get_status(&self, command_id: &str) -> Option<CommandStatusView> {
        self.0.get_status(command_id).await
    }

    pub async fn get_artifact(&self, command_id: &str) -> Option<(String, Vec<u8>)> {
        self.0.get_artifact(command_id).await
    }

    pub async fn connected_agent_ids(&self) -> Vec<String> {
        let agents = self.0.agents.lock().await;
        let mut ids: Vec<String> = agents.keys().cloned().collect();
        ids.sort();
        ids
    }
}

struct AgentConnection {
    tx: mpsc::Sender<ResponseCommand>,
}

struct StoredCommand {
    command: ResponseCommand,
    status: ResultStatus,
    message: String,
    issued_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    artifact_name: Option<String>,
    artifact: Option<Vec<u8>>,
}

pub struct ResponseHub {
    agents: Mutex<HashMap<String, AgentConnection>>,
    commands: Mutex<HashMap<String, StoredCommand>>,
}

impl ResponseHub {
    fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            commands: Mutex::new(HashMap::new()),
        }
    }

    fn prune_commands(commands: &mut HashMap<String, StoredCommand>) {
        const MAX_COMMANDS: usize = 4096;

        if commands.len() <= MAX_COMMANDS {
            return;
        }

        // Prefer pruning completed commands first; keep the most recent items.
        // Sort key: (is_completed, completed_or_issued_time)
        let mut keys: Vec<String> = commands.keys().cloned().collect();
        keys.sort_by_key(|k| {
            let c = commands.get(k);
            let (completed, t) = match c {
                Some(sc) => {
                    let is_completed = sc.completed_at.is_some();
                    let ts = sc.completed_at.unwrap_or(sc.issued_at);
                    (is_completed, ts)
                }
                None => (false, DateTime::<Utc>::MIN_UTC),
            };
            (completed, t)
        });

        let drop_n = keys.len().saturating_sub(MAX_COMMANDS);
        for k in keys.into_iter().take(drop_n) {
            commands.remove(&k);
        }
    }

    async fn register_agent(&self, agent_id: String, tx: mpsc::Sender<ResponseCommand>) {
        let id = agent_id.trim().to_string();
        self.agents.lock().await.insert(id, AgentConnection { tx });
    }

    async fn unregister_agent(&self, agent_id: &str) {
        self.agents.lock().await.remove(agent_id);
    }

    async fn rekey_agent(&self, old_agent_id: &str, new_agent_id: &str) -> bool {
        let old_id = old_agent_id.trim();
        let new_id = new_agent_id.trim();
        if old_id.is_empty() || new_id.is_empty() || old_id == new_id {
            return false;
        }

        let mut agents = self.agents.lock().await;
        let Some(conn) = agents.remove(old_id) else {
            return false;
        };
        agents.insert(new_id.to_string(), conn);
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch(
        &self,
        target_agent_id: &str,
        kind: CommandKind,
        ip: Option<String>,
        username: Option<String>,
        duration_seconds: u32,
        args: std::collections::HashMap<String, String>,
        custom_kind: Option<String>,
    ) -> Result<String, Status> {
        let command_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let issued_at = Some(prost_types::Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        });

        let cmd = ResponseCommand {
            command_id: command_id.clone(),
            target_agent_id: target_agent_id.to_string(),
            kind: kind as i32,
            ip: ip.unwrap_or_default(),
            username: username.unwrap_or_default(),
            duration_seconds,
            args,
            custom_kind: custom_kind.unwrap_or_default(),
            issued_at,
        };

        {
            let mut commands = self.commands.lock().await;
            commands.insert(
                command_id.clone(),
                StoredCommand {
                    command: cmd.clone(),
                    status: ResultStatus::Started,
                    message: "dispatched".to_string(),
                    issued_at: now,
                    completed_at: None,
                    artifact_name: None,
                    artifact: None,
                },
            );
            Self::prune_commands(&mut commands);
        }

        let agents = self.agents.lock().await;
        let Some(conn) = agents.get(target_agent_id) else {
            return Err(Status::not_found("agent_not_connected"));
        };

        conn.tx
            .send(cmd)
            .await
            .map_err(|_| Status::unavailable("agent_channel_closed"))?;

        Ok(command_id)
    }

    async fn update_from_result(&self, result: ResponseResult) {
        let command_id = result.command_id.clone();
        if command_id.is_empty() {
            return;
        }

        let status = match ResultStatus::try_from(result.status) {
            Ok(s) => s,
            Err(_) => ResultStatus::ResultUnknown,
        };

        let completed_at = if let Some(ts) = &result.completed_at {
            let secs = ts.seconds;
            let nanos = ts.nanos.max(0) as u32;
            DateTime::<Utc>::from_timestamp(secs, nanos)
        } else {
            None
        };

        let mut commands = self.commands.lock().await;
        let Some(entry) = commands.get_mut(&command_id) else {
            // Unknown command id: ignore (agent may be reconnecting or late-reporting)
            debug!("Ignoring result for unknown command_id={}", command_id);
            return;
        };

        // Prefer terminal states and non-empty messages.
        if status != ResultStatus::Heartbeat {
            entry.status = status;
        }
        if !result.message.trim().is_empty() {
            entry.message = result.message;
        }
        if completed_at.is_some() {
            entry.completed_at = completed_at;
        }
        if !result.artifact_name.trim().is_empty() && !result.artifact.is_empty() {
            entry.artifact_name = Some(result.artifact_name);
            entry.artifact = Some(result.artifact);
        }

        Self::prune_commands(&mut commands);
    }

    async fn get_status(&self, command_id: &str) -> Option<CommandStatusView> {
        let commands = self.commands.lock().await;
        let c = commands.get(command_id)?;
        Some(CommandStatusView {
            command_id: c.command.command_id.clone(),
            target_agent_id: c.command.target_agent_id.clone(),
            kind: c.command.kind,
            ip: c.command.ip.clone(),
            username: c.command.username.clone(),
            duration_seconds: c.command.duration_seconds,
            custom_kind: c.command.custom_kind.clone(),
            args: c.command.args.clone(),
            status: c.status as i32,
            message: c.message.clone(),
            issued_at_rfc3339: c.issued_at.to_rfc3339(),
            completed_at_rfc3339: c.completed_at.map(|t| t.to_rfc3339()),
            artifact_name: c.artifact_name.clone(),
            has_artifact: c.artifact.as_ref().map(|a| !a.is_empty()).unwrap_or(false),
        })
    }

    async fn get_artifact(&self, command_id: &str) -> Option<(String, Vec<u8>)> {
        let commands = self.commands.lock().await;
        let c = commands.get(command_id)?;
        let name = c.artifact_name.clone()?;
        let bytes = c.artifact.clone()?;
        Some((name, bytes))
    }
}

#[derive(Clone)]
pub struct ResponseService {
    ca_service: Arc<CAService>,
    hub: Arc<ResponseHub>,
}

impl ResponseService {
    pub fn new(ca_service: Arc<CAService>, hub: ResponseHubHandle) -> Self {
        Self {
            ca_service,
            hub: hub.0,
        }
    }
}

#[tonic::async_trait]
impl ResponseServiceTrait for ResponseService {
    type CommandStreamStream = ReceiverStream<Result<ResponseCommand, Status>>;

    async fn command_stream(
        &self,
        request: Request<tonic::Streaming<ResponseResult>>,
    ) -> Result<Response<Self::CommandStreamStream>, Status> {
        let peer_cert_der = mtls_peer::peer_cert_der(&request);
        let agent_cn: Option<String> =
            mtls_peer::validate_peer_der_and_get_cn(peer_cert_der, &self.ca_service).await?;
        // In plaintext/dev scenarios there may be no peer certificate.
        // Use a unique placeholder so multiple connections don't collide; allow the agent
        // to "re-key" itself via a heartbeat that includes `agent_id`.
        //
        // In mTLS scenarios, the peer cert CN is the authoritative identity for this channel.
        // Do NOT allow a client to re-key to an arbitrary `agent_id` (that can break
        // endpoint-response dispatch correctness and is a security footgun).
        let cn_trimmed = agent_cn.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let (agent_id, allow_rekey_via_heartbeat) = match cn_trimmed {
            Some(cn) => (cn.to_string(), false),
            None => (format!("<unknown:{}>", Uuid::new_v4()), true),
        };

        let (tx, rx) = mpsc::channel::<Result<ResponseCommand, Status>>(128);
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ResponseCommand>(128);

        self.hub.register_agent(agent_id.clone(), cmd_tx).await;
        info!("🛰️  Response channel connected: agent={}", agent_id);

        // Forward queued commands into tonic stream.
        let tx_forward = tx.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if tx_forward.send(Ok(cmd)).await.is_err() {
                    break;
                }
            }
        });

        // Consume incoming results from agent.
        let hub = self.hub.clone();
        let agent_id_for_task = agent_id.clone();
        tokio::spawn(async move {
            let mut effective_agent_id = agent_id_for_task.clone();
            let mut inbound = request.into_inner();
            while let Some(msg) = inbound.message().await.transpose() {
                match msg {
                    Ok(res) => {
                        // If we don't have mTLS identity, allow the agent to identify itself
                        // via a heartbeat result. This enables endpoint response in plaintext/dev.
                        if res.command_id.trim().is_empty() {
                            if ResultStatus::try_from(res.status).ok()
                                == Some(ResultStatus::Heartbeat)
                            {
                                let reported = res.agent_id.trim();
                                if allow_rekey_via_heartbeat
                                    && !reported.is_empty()
                                    && reported != effective_agent_id
                                    && hub.rekey_agent(&effective_agent_id, reported).await
                                {
                                    info!(
                                        "🛰️  Response channel re-keyed: {} -> {}",
                                        effective_agent_id, reported
                                    );
                                    effective_agent_id = reported.to_string();
                                }
                            }
                            continue;
                        }

                        // Best-effort attribution.
                        if !res.agent_id.trim().is_empty() && res.agent_id != effective_agent_id {
                            debug!(
                                "Agent reported agent_id '{}' but mTLS CN was '{}'",
                                res.agent_id, effective_agent_id
                            );
                        }
                        hub.update_from_result(res).await;
                    }
                    Err(e) => {
                        warn!(
                            "Response channel inbound error for {}: {}",
                            effective_agent_id, e
                        );
                        break;
                    }
                }
            }

            hub.unregister_agent(&effective_agent_id).await;
            info!(
                "🛰️  Response channel disconnected: agent={}",
                effective_agent_id
            );
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
