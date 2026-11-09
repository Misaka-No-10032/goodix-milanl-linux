use crate::{
    Secret,
    error::{Error, Result},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) struct State {
    directory: PathBuf,
}

impl State {
    pub(crate) fn open(directory: &Path) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(Error::Device(
                "calibration directory must be private and owned by the service user",
            ));
        }
        Ok(Self {
            directory: directory.to_owned(),
        })
    }

    pub(crate) fn read(&self, name: &str, maximum: usize) -> Result<Secret> {
        Ok(self.read_optional(name, maximum)?.unwrap_or_default())
    }

    pub(crate) fn read_optional(&self, name: &str, maximum: usize) -> Result<Option<Secret>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join(name))
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Self::check_file(&file)?;
        let mut bytes = Secret::new(Vec::new());
        file.take(maximum as u64).read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join(name))?;
        Self::check_file(&file)?;
        file.set_len(0)?;
        file.write_all(bytes)?;
        Ok(())
    }

    pub(crate) fn remove(&self, name: &str) -> Result<()> {
        self.read(name, 0)?;
        match fs::remove_file(self.directory.join(name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => self.write(name, &[]),
        }
    }

    fn check_file(file: &File) -> Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(Error::Device(
                "calibration file must be private and owned by the service user",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "milanl-state-{}-{}", std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn calibration_survives_reopening_with_private_modes() {
        let directory = Directory::new();
        let state = State::open(&directory.0).unwrap();
        assert!(state.read("calibration", 16).unwrap().is_empty());
        state.write("calibration", &[42; 16]).unwrap();
        drop(state);
        let state = State::open(&directory.0).unwrap();
        assert_eq!(&*state.read("calibration", 16).unwrap(), &[42; 16]);
        assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(directory.0.join("calibration"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        state.write("calibration", &[7; 8]).unwrap();
        assert_eq!(&*state.read("calibration", 16).unwrap(), &[7; 8]);
        assert_eq!(&*state.read("calibration", 7).unwrap(), &[7; 7]);
        state.remove("calibration").unwrap();
        assert!(state.read("calibration", 16).unwrap().is_empty());
        state.remove("calibration").unwrap();
    }

    #[test]
    fn files_are_checked_before_overwriting() {
        let directory = Directory::new();
        let state = State::open(&directory.0).unwrap();
        state.write("calibration", &[42; 16]).unwrap();
        let path = directory.0.join("calibration");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(state.write("calibration", &[7]).is_err());
        assert_eq!(fs::read(&path).unwrap(), [42; 16]);
        symlink(&path, directory.0.join("link")).unwrap();
        assert!(state.read("link", 16).is_err());
        assert!(state.write("link", &[7]).is_err());
    }

    #[test]
    fn shared_directory_is_not_accepted() {
        let directory = Directory::new();
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(State::open(&directory.0).is_err());
    }
}
