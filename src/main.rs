use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

mod gitrepo;
mod overlays;
mod re;

const GENTOO_META_REPO_ORIGIN: &str = "https://github.com/gentoo/api-gentoo-org/";
const GENTO_META_REPO_REPO_LIST: &str = "files/overlays/repositories.xml";

#[derive(clap::Clap, Debug)]
struct Opts {
    #[clap(long, short = 'O')]
    offline: bool,
    #[clap(long, short = 'd')]
    work_dir: PathBuf,
}

lazy_static::lazy_static! {
    static ref OPTS: Opts = clap::Clap::parse();
}

fn format_chain(e: &anyhow::Error) -> String {
    e.chain()
        .map(|c| format!("\n\t{}", c))
        .collect::<Vec<_>>()
        .join("")
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    log::trace!("Opts: {:#?}", *OPTS);

    //let advisory_db_url = rustsec::repository::git::DEFAULT_URL;
    //upclone(advisory_db_url, &basepath.join("rustsec-advisories")).context("Fetch advisories")?;
    //
    //let crates_io = cargo::sources::registry::CRATES_IO_INDEX;
    //upclone(crates_io, &basepath.join("crates.io")).context("Fetch crates.io")?;

    //.context("Fetch gentoo overlay list")
    //

    let overlays = fgo()?;
    let pool = rayon::ThreadPoolBuilder::new().build().unwrap();

    pool.scope(|scope| {
        for overlay in overlays {
            scope.spawn(move |_scope| {
                let act = (|| -> Result<()> {
                    fn source_goodness(url: &str) -> i8 {
                        if url.starts_with("git://") {
                            -2
                        } else if url.starts_with("https://") {
                            -1
                        } else if url.starts_with("git@") {
                            1
                        } else if url.starts_with("git+ssh://") {
                            2
                        } else if url.starts_with("ssh+git://") {
                            2
                        } else {
                            0
                        }
                    }
                    let mut sources = overlay
                        .sources
                        .iter()
                        .filter(|s| s.typ == overlays::SourceType::Git)
                        .collect::<Vec<_>>();
                    if sources.is_empty() {
                        log::info!("No git source for {}, ignoring", overlay.name);
                        return Ok(());
                    };
                    sources.sort_by_key(|s| source_goodness(&s.url));
                    let repopath = &OPTS.work_dir.join("overlays").join(&overlay.name);
                    if OPTS.offline && !repopath.exists() {
                        log::info!("Overlay {} not cloned yet, skipping in offline mode", overlay.name);
                        return Ok(());
                    }
                    let repo = gitrepo::RepoRepo::on(repopath)?;

                    let mut head = repo
                        .repo()
                        .head()
                        .context("Fetch failed, use previous HEAD");
                    if !OPTS.offline {
                        for source in sources {
                            match repo.up(&source.url) {
                                h @ Ok(_) => {
                                    head = h;
                                    break;
                                }
                                Err(e) => {
                                    log::error!(
                                        "Failed to update overlay {} with source {}:{}",
                                        overlay.name,
                                        source.url,
                                        format_chain(&e),
                                    );
                                }
                            }
                        }
                    }
                    if OPTS.offline && head.is_err() {
                        log::info!("Overlay {}'s repository exists but has no HEAD, skipping in offline mode", overlay.name);
                        return Ok(());
                    }
                    let head = head?;

                    head.peel_to_tree()?
                        .walk(
                            git2::TreeWalkMode::PreOrder,
                            find_cargo_ebuilds(repo.repo(), &overlay.name),
                        )
                        .context("Search HEAD tree")?;

                    Ok(())
                })();
                if let Err(e) = act {
                    log::error!(
                        "Failed to process overlay {}:{}",
                        overlay.name,
                        format_chain(&e),
                    );
                    // TODO: Set exit code if this is on the "gentoo" overlay
                };
            });
        }
    });

    Ok(())
}

fn find_cargo_ebuilds<'a>(
    repo: &'a git2::Repository,
    overlay: &'a str,
) -> impl 'a + FnMut(&str, &git2::TreeEntry<'_>) -> git2::TreeWalkResult {
    move |root, entry| {
        if Some(git2::ObjectType::Blob) == entry.kind() {
            if let Some(name) = entry.name() {
                if name.ends_with(".ebuild") {
                    let content = entry.to_object(repo).unwrap();
                    let content = content.as_blob().expect("Object blob").content();
                    let content = String::from_utf8_lossy(content);
                    if content.contains("cargo_crate_uris ")
                        || re::USES_CARGO_ECLASS.is_match(&content)
                    {
                        parse(overlay, &format!("{}{}", root, name), &content);
                    }
                }
            }
        }
        git2::TreeWalkResult::Ok
    }
}

#[derive(Debug, Clone)]
struct DepInfo {
    name: String,
    ver: String,
}
fn parse(overlay: &str, path: &str, content: &str) {
    if !content.contains(r"$(cargo_crate_uris ${CRATES})")
        && !content.contains(r"$(cargo_crate_uris $CRATES)")
    {
        if content.contains("cargo_crate_uris") {
            log::warn!(
                "{}::{}: Non-standard usage of cargo_create_uris",
                overlay,
                path,
            );
        } else {
            log::info!(
                "{}::{}: Uses cargo, but does not use cargo_crate_uris - skipped",
                overlay,
                path,
            );
            return;
        }
    }
    if let Some(capt) = re::CRATES.captures(content) {
        let crates = &capt[1];
        let crates = match re::split_pkgver(path) {
            Some((pn, pv)) => {
                crates
                    .replace("${P}", &format!("{}-{}", pn, pv))
                    .replace("${PV}", pv)
                    .replace("${PN}", pn)
            },
            None => {
                log::warn!("{}::{}: Strange ebuild name, can't get PN/PV", overlay, path);
                crates.to_string()
            }
        };
        let res = crates
            .split_whitespace()
            .filter_map(|spec_str| match re::DEPSPEC.captures(spec_str) {
                Some(capt) => Some(DepInfo {
                    name: capt[1].to_string(),
                    ver: capt[2].to_string(),
                }),
                None => {
                    log::warn!(
                        "{}::{}: Could not parse dependency {}",
                        overlay,
                        path,
                        spec_str,
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        println!("{}::{}: {:#?}", overlay, path, res);
    } else {
        log::warn!(
            "{}::{}: Could not get declaration of CRATES list",
            overlay,
            path,
        );
    }
}

fn fgo() -> Result<Vec<overlays::Overlay>> {
    Ok((|| -> Result<_> {
        let gentoo_meta = gitrepo::RepoRepo::on(&OPTS.work_dir.join("gentoo"))?;
        let head = gentoo_meta.up(GENTOO_META_REPO_ORIGIN)?;
        let tree = head.peel_to_tree()?;
        let ret = overlays::parse(
            tree.get_path(&Path::new(GENTO_META_REPO_REPO_LIST))?
                .to_object(gentoo_meta.repo())?
                .as_blob()
                .context("Tree file as blob")?
                .content(),
        )
        .context("Parse")?;
        Ok(ret) // Headscratcher: If I don't define ret, the borrow checker cries...
    })()
    .context("Obtain gentoo overlay list")?)
}
