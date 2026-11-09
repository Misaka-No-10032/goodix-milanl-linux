//! libfprint wire protocol v2. Biometric payloads contain sealed templates only.

use crate::{
    Secret,
    error::{Error, Result},
};

pub const VERSION: u32 = 2;
pub const ENROLL_STAGES: u16 = 12;
pub const MAX_BLOB: usize = 1024 * 1024;
pub const MAX_GALLERY: usize = 16;
pub const MAX_MESSAGE: usize = MAX_GALLERY * (MAX_BLOB + 4) + 3;
pub const VERIFY_INDEX: u16 = u16::MAX;

pub enum Request<'a> {
    Hello,
    EnrollBegin,
    EnrollCapture,
    Verify(&'a [u8]),
    Identify(Vec<&'a [u8]>),
    Cancel,
    Suspend,
    Resume,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum ErrorCode {
    General = 1,
    Protocol = 2,
    Data = 5,
}

pub enum Response {
    Ok,
    Hello,
    EnrollStage(u16),
    EnrollDone(Secret),
    Match { index: u16, updated: Option<Secret> },
    NoMatch,
    Retry,
    Error(ErrorCode),
    Interrupted,
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.0.len() {
            return Err(Error::Protocol("truncated request"));
        }
        let (field, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(field)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn blob(&mut self) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        if length > MAX_BLOB {
            return Err(Error::Protocol("template exceeds wire limit"));
        }
        self.take(length)
    }
}

impl<'a> Request<'a> {
    pub fn decode(body: &'a [u8]) -> Result<Self> {
        if body.is_empty() || body.len() > MAX_MESSAGE {
            return Err(Error::Protocol("message length out of range"));
        }
        let mut input = Cursor(body);
        let request = match input.take(1)?[0] {
            1 => {
                if input.u32()? != VERSION {
                    return Err(Error::Protocol("unsupported version"));
                }
                Self::Hello
            }
            2 => Self::EnrollBegin,
            3 => Self::EnrollCapture,
            4 => Self::Verify(input.blob()?),
            5 => {
                let count = input.u16()? as usize;
                if count > MAX_GALLERY {
                    return Err(Error::Protocol("gallery exceeds wire limit"));
                }
                let mut gallery = Vec::with_capacity(count);
                for _ in 0..count {
                    gallery.push(input.blob()?);
                }
                Self::Identify(gallery)
            }
            6 => Self::Cancel,
            7 => Self::Suspend,
            8 => Self::Resume,
            _ => return Err(Error::Protocol("unknown operation")),
        };
        if !input.0.is_empty() {
            return Err(Error::Protocol("trailing request data"));
        }
        Ok(request)
    }
}

impl Response {
    pub fn encode(&self) -> Result<Secret> {
        let length = match self {
            Self::Ok | Self::NoMatch | Self::Interrupted => 1,
            Self::Hello => 11,
            Self::EnrollStage(stage) if (1..ENROLL_STAGES).contains(stage) => 3,
            Self::EnrollStage(_) => return Err(Error::Enclave("invalid enrollment progress")),
            Self::EnrollDone(blob) => 5 + checked_blob_size(blob)?,
            Self::Match { index, updated } => {
                if *index != VERIFY_INDEX && *index as usize >= MAX_GALLERY {
                    return Err(Error::Enclave("invalid match index"));
                }
                4 + match updated {
                    Some(blob) => 4 + checked_blob_size(blob)?,
                    None => 0,
                }
            }
            Self::Retry | Self::Error(_) => 2,
        };
        let mut body = Secret::new(Vec::with_capacity(length));
        match self {
            Self::Ok => body.push(1),
            Self::Hello => {
                body.push(2);
                body.extend_from_slice(&VERSION.to_le_bytes());
                body.extend_from_slice(&ENROLL_STAGES.to_le_bytes());
                body.extend_from_slice(&3u32.to_le_bytes()); // IDENTIFY | ADAPT
            }
            Self::EnrollStage(stage) => {
                body.push(3);
                body.extend_from_slice(&stage.to_le_bytes());
            }
            Self::EnrollDone(blob) => {
                body.push(4);
                append_blob(&mut body, blob);
            }
            Self::Match { index, updated } => {
                body.push(5);
                body.extend_from_slice(&index.to_le_bytes());
                body.push(u8::from(updated.is_some()));
                if let Some(blob) = updated {
                    append_blob(&mut body, blob);
                }
            }
            Self::NoMatch => body.push(6),
            Self::Retry => body.extend_from_slice(&[7, 1]),
            Self::Error(code) => body.extend_from_slice(&[8, *code as u8]),
            Self::Interrupted => body.push(9),
        }
        Ok(body)
    }
}

fn checked_blob_size(blob: &[u8]) -> Result<usize> {
    if !(560..=MAX_BLOB).contains(&blob.len()) {
        return Err(Error::Enclave("invalid sealed template length"));
    }
    Ok(blob.len())
}

fn append_blob(output: &mut Vec<u8>, blob: &[u8]) {
    output.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    output.extend_from_slice(blob);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_matches_c_protocol_v2() {
        assert!(matches!(
            Request::decode(&[1, 2, 0, 0, 0]).unwrap(),
            Request::Hello
        ));
        assert_eq!(
            &*Response::Hello.encode().unwrap(),
            &[2, 2, 0, 0, 0, 12, 0, 3, 0, 0, 0]
        );
        assert!(Request::decode(&[1, 1, 0, 0, 0]).is_err());
        assert_eq!(&*Response::Interrupted.encode().unwrap(), &[9]);
    }

    #[test]
    fn complete_requests_are_required() {
        for invalid in [
            vec![],
            vec![1],
            vec![2, 0],
            vec![4, 1, 0, 0, 0],
            vec![5, 17, 0],
            vec![5, 1, 0],
            vec![0],
            vec![9],
        ] {
            assert!(Request::decode(&invalid).is_err());
        }
        for operation in [2, 3, 6, 7, 8] {
            assert!(Request::decode(&[operation]).is_ok());
        }
    }

    #[test]
    fn gallery_borrows_all_candidates_without_filtering() {
        let body = [5, 2, 0, 1, 0, 0, 0, 42, 2, 0, 0, 0, 11, 12];
        let Request::Identify(gallery) = Request::decode(&body).unwrap() else {
            panic!()
        };
        assert_eq!(gallery, [&[42][..], &[11, 12][..]]);
        assert!(
            matches!(Request::decode(&[5, 0, 0]).unwrap(), Request::Identify(v) if v.is_empty())
        );
    }

    #[test]
    fn blob_and_message_bounds_precede_allocation() {
        let mut body = vec![4];
        body.extend_from_slice(&((MAX_BLOB + 1) as u32).to_le_bytes());
        assert!(Request::decode(&body).is_err());
        assert!(Request::decode(&vec![0; MAX_MESSAGE + 1]).is_err());
    }

    #[test]
    fn match_layout_and_adaptation_are_exact() {
        assert_eq!(
            &*Response::Match {
                index: VERIFY_INDEX,
                updated: None
            }
            .encode()
            .unwrap(),
            &[5, 255, 255, 0]
        );
        let body = Response::Match {
            index: 1,
            updated: Some(Secret::new(vec![42; 560])),
        }
        .encode()
        .unwrap();
        assert_eq!(&body[..8], &[5, 1, 0, 1, 48, 2, 0, 0]);
        assert_eq!(body.len(), 568);
        assert!(
            Response::Match {
                index: 16,
                updated: None
            }
            .encode()
            .is_err()
        );
        assert!(
            Response::EnrollDone(Secret::new(vec![0; 559]))
                .encode()
                .is_err()
        );
        assert!(Response::EnrollStage(12).encode().is_err());
    }
}
