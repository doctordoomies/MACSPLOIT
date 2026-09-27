use crate::{
    assets::Id,
    database::{rows, Store},
    error::{CoreError, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Id,
    pub workspace_id: Id,
    pub provider_run_id: Id,
    pub provider: String,
    pub target: String,
    pub timestamp: String,
    pub sha256: String,
    pub media_type: String,
    pub relative_path: String,
    pub byte_count: usize,
}

pub fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

impl Store {
    pub fn write_evidence(
        &self,
        workspace_id: Id,
        run: Id,
        provider: &str,
        target: &str,
        raw: &[u8],
    ) -> Result<Evidence> {
        if raw.len() > 1024 * 1024 {
            return Err(CoreError::new("BudgetExceeded", "Evidence exceeds 1 MiB."));
        }
        self.connect(workspace_id)?;
        let id = Id::new_v4();
        let relative_path = format!("evidence/{id}.json");
        let directory = self.directory(workspace_id).join("evidence");
        crate::database::private_directory(&directory)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory(workspace_id).join(&relative_path))?;
        file.write_all(raw)?;
        file.sync_all()?;
        Ok(Evidence {
            id,
            workspace_id,
            provider_run_id: run,
            provider: provider.into(),
            target: target.into(),
            timestamp: crate::now(),
            sha256: digest(raw),
            media_type: "application/json".into(),
            relative_path,
            byte_count: raw.len(),
        })
    }

    pub fn read_evidence(&self, workspace_id: Id, id: Id) -> Result<String> {
        let conn = self.connect(workspace_id)?;
        let evidence: Evidence = rows(
            &conn,
            &format!("{EVIDENCE_SELECT} WHERE workspace_id=?1 AND id=?2"),
            rusqlite::params![workspace_id.to_string(), id.to_string()],
        )?
        .into_iter()
        .next()
        .ok_or_else(|| {
            CoreError::new(
                "EvidenceNotFound",
                "Evidence does not exist in this workspace.",
            )
        })?;
        let expected = format!("evidence/{id}.json");
        if evidence.relative_path != expected {
            return Err(CoreError::new(
                "StorageError",
                "Evidence path violates workspace containment.",
            ));
        }
        let directory = self.directory(workspace_id).join("evidence");
        let path = directory.join(format!("{id}.json"));
        if fs::symlink_metadata(&directory)?.file_type().is_symlink()
            || fs::symlink_metadata(&path)?.file_type().is_symlink()
            || fs::metadata(&path)?.len() > 1024 * 1024
        {
            return Err(CoreError::new(
                "StorageError",
                "Evidence file violates storage limits.",
            ));
        }
        let raw = fs::read(path)?;
        if digest(&raw) != evidence.sha256 {
            return Err(CoreError::new(
                "EvidenceIntegrityError",
                "Stored evidence failed its SHA-256 integrity check.",
            ));
        }
        String::from_utf8(raw).map_err(|_| CoreError::new("InvalidData", "Evidence is not UTF-8."))
    }
}

pub const EVIDENCE_SELECT: &str = "SELECT json_object('id',id,'workspace_id',workspace_id,'provider_run_id',provider_run_id,'provider',provider,'target',target,'timestamp',timestamp,'sha256',sha256,'media_type',media_type,'relative_path',relative_path,'byte_count',byte_count) FROM evidence";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_hash_matches_known_sha256() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
