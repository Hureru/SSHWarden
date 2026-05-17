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
    let mut data = Bytes::copy_from_slice(data);
    let magic_header = "SSHSIG";
    let header = data.split_to(magic_header.len());

    if header == magic_header.as_bytes() {
        let _version = data.get_u32();

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
