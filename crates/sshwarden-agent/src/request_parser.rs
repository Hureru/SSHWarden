use bytes::{Buf, Bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    SshAuthentication,
    GitSigning,
    FileSigning,
    SshSignature,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SshAuthentication => "ssh_authentication",
            Self::GitSigning => "git_signing",
            Self::FileSigning => "file_signing",
            Self::SshSignature => "ssh_signature",
        }
    }
}

#[derive(Debug)]
pub(crate) struct SshSigRequest {
    pub namespace: String,
}

#[derive(Debug)]
pub(crate) struct SignRequest {}

#[derive(Debug)]
pub(crate) enum SshAgentSignRequest {
    SshSigRequest(SshSigRequest),
    SignRequest(SignRequest),
}

impl SshAgentSignRequest {
    pub fn operation_kind(&self) -> OperationKind {
        match self {
            Self::SignRequest(_) => OperationKind::SshAuthentication,
            Self::SshSigRequest(req) => operation_kind_from_namespace(&req.namespace),
        }
    }
}

fn operation_kind_from_namespace(namespace: &str) -> OperationKind {
    match namespace {
        "git" => OperationKind::GitSigning,
        "file" => OperationKind::FileSigning,
        "ssh" => OperationKind::SshAuthentication,
        _ => OperationKind::SshSignature,
    }
}

pub(crate) fn parse_request(data: &[u8]) -> Result<SshAgentSignRequest, anyhow::Error> {
    let magic_header = "SSHSIG";

    // A plain SSH signature request is just the raw data to be signed; only
    // SSHSIG blobs (git/file signing) carry a magic header + namespace. Any
    // payload shorter than the magic header cannot be an SSHSIG blob, so treat
    // it as a plain signature request rather than panicking in `split_to`.
    if data.len() < magic_header.len() {
        return Ok(SshAgentSignRequest::SignRequest(SignRequest {}));
    }

    let mut data = Bytes::copy_from_slice(data);
    let header = data.split_to(magic_header.len());

    if header == magic_header.as_bytes() {
        // SSHSIG = magic || u32 version || ... — guard the version read so a
        // truncated blob returns an error instead of panicking in `get_u32`.
        let _version = data
            .try_get_u32()
            .map_err(|_| anyhow::anyhow!("Truncated SSHSIG request: missing version"))?;

        let namespace = data
            .into_iter()
            .take_while(|&x| x != 0)
            .collect::<Vec<u8>>();
        let namespace =
            String::from_utf8(namespace).map_err(|_| anyhow::anyhow!("Invalid namespace"))?;

        Ok(SshAgentSignRequest::SshSigRequest(SshSigRequest {
            namespace,
        }))
    } else {
        Ok(SshAgentSignRequest::SignRequest(SignRequest {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EH-01: malformed / truncated payloads must never panic.
    #[test]
    fn empty_payload_is_plain_sign_request() {
        assert!(matches!(
            parse_request(&[]).expect("empty payload should not error"),
            SshAgentSignRequest::SignRequest(_)
        ));
    }

    #[test]
    fn short_payloads_below_magic_len_never_panic() {
        for len in 0.."SSHSIG".len() {
            let data = vec![b'S'; len];
            assert!(matches!(
                parse_request(&data).expect("short payload should not error"),
                SshAgentSignRequest::SignRequest(_)
            ));
        }
    }

    #[test]
    fn sshsig_magic_without_version_returns_err_not_panic() {
        // Exactly the magic header, then 0..4 trailing bytes (version is u32).
        for trailing in 0..4usize {
            let mut data = b"SSHSIG".to_vec();
            data.extend(std::iter::repeat_n(0u8, trailing));
            assert!(
                parse_request(&data).is_err(),
                "truncated SSHSIG (trailing={trailing}) should error, not panic"
            );
        }
    }

    #[test]
    fn well_formed_sshsig_parses_namespace() {
        let mut data = b"SSHSIG".to_vec();
        data.extend_from_slice(&1u32.to_be_bytes()); // version
        data.extend_from_slice(b"git\0rest");
        match parse_request(&data).expect("well-formed SSHSIG should parse") {
            SshAgentSignRequest::SshSigRequest(req) => assert_eq!(req.namespace, "git"),
            other => panic!("expected SshSigRequest, got {other:?}"),
        }
    }

    #[test]
    fn non_sshsig_payload_is_plain_sign_request() {
        assert!(matches!(
            parse_request(b"not-a-sshsig-blob-just-raw-bytes")
                .expect("non-SSHSIG payload should not error"),
            SshAgentSignRequest::SignRequest(_)
        ));
    }
}
