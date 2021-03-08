use anyhow::{Context, Result};
use std::borrow::Cow;
use std::fs;
use std::path::Path;

// Brr. cargo doesn't expose the function, rustsec copies and modifies it, with its own result type.
fn with_git_default_auth<T, F>(url: &str, mut f: F) -> T
where
    F: FnMut(&mut git2::Credentials<'_>) -> T,
{
    rustsec::repository::git::with_authentication(
        url,
        &git2::Config::new().expect("Git config"),
        |creds| Ok(f(creds)),
    )
    .unwrap()
}

pub struct RepoRepo {
    repo: git2::Repository,
}

impl RepoRepo {
    pub fn on(path: &Path) -> Result<Self> {
        if path.is_dir() && fs::read_dir(&path)?.next().is_none() {
            log::warn!("Cleaning empty dir {}", path.to_string_lossy());
            fs::remove_dir(&path)?;
        }

        let repo = if path.is_dir() {
            git2::Repository::open_bare(path).context("Open existing repository")
        } else {
            let mut iopts = git2::RepositoryInitOptions::new();
            iopts.bare(true);
            iopts.external_template(false);
            git2::Repository::init_opts(path, &iopts).context("Init new bare repository")
        };
        let repo = repo.context(format!("Repo at {}", path.to_string_lossy()))?;

        Ok(RepoRepo { repo })
    }

    pub fn up(&self, url: &str) -> Result<git2::Reference> {
        let url = match url.starts_with("ssh+git://") || url.starts_with("git+ssh://") {
            true => &url[10..],
            false => url,
        };
        Ok(with_git_default_auth(url, |creds| -> Result<_> {
            let mut remo = self.repo.remote_anonymous(url)?;

            let mut proxy_opts = git2::ProxyOptions::new();
            proxy_opts.auto();

            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(creds);
            remo.connect_auth(git2::Direction::Fetch, Some(callbacks), Some(proxy_opts))?;

            let head = remo.list().context("Reflist")?.get(0).context("Get HEAD")?;
            let head_oid = head.oid();
            let head_name = head.name().to_string();
            let srt = head.symref_target().map(str::to_string);
            log::debug!(
                "Fetch {} to {}: default branch: {}{} -> {}",
                url,
                self.path(),
                head_name,
                srt.as_ref()
                    .map(|srt| format!(" {} ->", srt))
                    .unwrap_or(String::new()),
                head_oid
            );

            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.sideband_progress(|prg| {
                log::trace!(
                    "Fetch {} to {}: {}",
                    url,
                    self.path(),
                    String::from_utf8_lossy(prg)
                );
                true
            });
            let mut fetch_opts = git2::FetchOptions::new();
            fetch_opts.remote_callbacks(callbacks);
            remo.download(&[&head_name], Some(&mut fetch_opts))
                .context("Fetch")?;

            remo.disconnect()?;
            std::mem::drop(remo);

            if let Some(srt) = srt {
                self.repo
                    .reference(
                        &srt,
                        head_oid,
                        true,
                        &format!("Update {} from {}", srt, url),
                    )
                    .context("Store head")?;
            }
            let head = self
                .repo
                .reference(&head_name, head_oid, true, &format!("Update from {}", url))
                .context("Store head")?;

            // TODO: Prune

            Ok(head)
        })
        .context(format!("Fetch {} to {}", url, self.path()))?)
    }

    pub fn path(&self) -> Cow<'_, str> {
        self.repo.path().to_string_lossy()
    }

    pub fn repo(&self) -> &git2::Repository {
        &self.repo
    }
}
