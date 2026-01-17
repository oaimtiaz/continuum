//! Client management commands.

use anyhow::Result;
use continuum_proto::enrollment::v1::{
    enrollment_service_client::EnrollmentServiceClient, ListAuthorizedClientsRequest,
    RevokeClientRequest,
};
use tonic::transport::Channel;

use crate::utils::format_timestamp_secs;

/// List all authorized clients.
pub async fn list_clients(channel: Channel, json: bool) -> Result<()> {
    let mut client = EnrollmentServiceClient::new(channel);
    let response = client
        .list_authorized_clients(ListAuthorizedClientsRequest {})
        .await?
        .into_inner();

    if json {
        let clients_json: Vec<_> = response
            .clients
            .iter()
            .map(|c| {
                serde_json::json!({
                    "fingerprint": c.fingerprint,
                    "label": c.label,
                    "authorized_at": c.authorized_at,
                    "last_seen_at": c.last_seen_at,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&clients_json)?);
    } else if response.clients.is_empty() {
        println!("No authorized clients");
    } else {
        println!("Authorized Clients:");
        println!("{:-<60}", "");
        for c in &response.clients {
            let label = if c.label.is_empty() {
                "(no label)"
            } else {
                &c.label
            };
            println!("  {} {}", c.fingerprint, label);
            println!("    Authorized: {}", format_timestamp_secs(c.authorized_at));
            if c.last_seen_at > 0 {
                println!("    Last seen:  {}", format_timestamp_secs(c.last_seen_at));
            }
            println!();
        }
        println!("Total: {} client(s)", response.clients.len());
    }
    Ok(())
}

/// Revoke a client's authorization.
pub async fn revoke_client(channel: Channel, fingerprint: &str) -> Result<()> {
    let mut client = EnrollmentServiceClient::new(channel);
    let response = client
        .revoke_client(RevokeClientRequest {
            fingerprint: fingerprint.to_string(),
        })
        .await?
        .into_inner();

    if response.success {
        eprintln!("✓ Client {} revoked", fingerprint);
    } else {
        anyhow::bail!("Client {} not found", fingerprint);
    }
    Ok(())
}

