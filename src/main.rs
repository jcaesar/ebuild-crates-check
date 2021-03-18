use anyhow::{Context, Result};
use crossbeam_utils::atomic::AtomicCell;
use rustsec::package::{Name, Version};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

mod gitrepo;
mod overlays;
mod re;

const GENTOO_META_REPO_ORIGIN: &str = "https://github.com/gentoo/api-gentoo-org/";
const GENTO_META_REPO_REPO_LIST: &str = "files/overlays/repositories.xml";

#[derive(clap::Clap, Debug)]
#[clap(about,version,author)]
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, serde::Serialize, serde::Deserialize)]
struct Ebuild {
    overlay: String,
    path: String,
}

type EbuildDeps = dashmap::DashMap<Ebuild, Vec<DepInfo>>;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CrateStatus {
    #[serde(rename = "crate")]
    id: DepInfo,
    advisories: Vec<AdvisoryMeta>,
    yanked: Option<bool>,
    ebuilds: Vec<Ebuild>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct DepInfo {
    name: Name,
    ver: Version,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AdvisoryMeta {
    id: String,
    title: String,
    cvss: Option<cvss::v3::base::Base>,
}

impl AdvisoryMeta {
    fn from_advisory(a: &rustsec::Advisory) -> Self {
        AdvisoryMeta {
            id: a.metadata.id.as_str().to_string(),
            title: a.metadata.title.to_string(),
            cvss: a.metadata.cvss.clone(),
        }
    }
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    log::trace!("Opts: {:#?}", *OPTS);

    let overlays = fgo()?;
    let pool = rayon::ThreadPoolBuilder::new().build().unwrap();

    let mut yanks = Err(anyhow::anyhow!("crates.io not retrieved"));
    let mut rustsec_get = Err(anyhow::anyhow!("Rustsec repo not retrieved"));
    let sec_db_path = OPTS.work_dir.join("rustsec");
    let gentoo_overlay_status =
        AtomicCell::new(Err(anyhow::anyhow!("gentoo overlay not processed")));
    let deps = EbuildDeps::new();

    pool.scope(|scope| {
        scope.spawn(|_| {
            rustsec_get = (|| -> Result<_> {
                let repo = gitrepo::RepoRepo::on_checkout(&sec_db_path)?;
                repo.up_or_head(rustsec::repository::git::DEFAULT_URL, OPTS.offline)?;
                Ok(())
            })().context("Get rustsec");
        });
        scope.spawn(|_| {
            yanks = cio();
        });
        for overlay in overlays {
            scope.spawn(|_scope| {
                let overlay = overlay;
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
                            match repo.up_or_head(&source.url, OPTS.offline) {
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
                            find_cargo_ebuilds(repo.repo(), &overlay.name, &deps),
                        )
                        .context("Search HEAD tree")?;

                    Ok(())
                })();
                if overlay.name == "gentoo" {
                    gentoo_overlay_status.store(act);
                } else if let Err(e) = act {
                    log::error!(
                        "Failed to process overlay {}:{}",
                        overlay.name,
                        format_chain(&e),
                    );
                };
            });
        }
    });

    let yanks = yanks?;
    gentoo_overlay_status.swap(Ok(()))?;
    rustsec_get?;
    let sec_db = rustsec::repository::git::Repository::open(&sec_db_path).context(format!(
        "Failed to open rustsec db at {}",
        sec_db_path.to_string_lossy()
    ))?;
    anyhow::ensure!(
        sec_db.latest_commit()?.is_fresh(),
        "Rustsec database is stale"
    );
    let sec_db = rustsec::database::Database::load_from_repo(&sec_db)
        .context("Load rustsec DB from repo")?;
    let sec_db_info = rustsec::report::DatabaseInfo::new(&sec_db);
    log::info!("rustsec: {:?}", sec_db_info);
    anyhow::ensure!(
        sec_db_info.advisory_count > 0,
        "0 advisories found. Sounds  wrong."
    );

    let mut crates = HashMap::new();
    for e in &deps {
        for dep in e.value() {
            crates
                .entry(dep.clone())
                .or_insert_with(|| {
                    let sec_query = rustsec::database::Query::crate_scope()
                        .package_version(dep.name.clone(), dep.ver.clone());
                    let advisories = sec_db
                        .query(&sec_query)
                        .into_iter()
                        .map(AdvisoryMeta::from_advisory)
                        .collect();
                    let yanked = yanks
                        .get(&dep.name)
                        .and_then(|vs| vs.get(&dep.ver))
                        .map(|v| *v);
                    CrateStatus {
                        id: dep.clone(),
                        ebuilds: vec![],
                        yanked,
                        advisories,
                    }
                })
                .ebuilds
                .push((*e.key()).clone());
        }
    }
    let mut crates = crates.into_iter().map(|(_, v)| v).collect::<Vec<_>>();
    std::mem::drop(deps);

    crates.sort_by_cached_key(|e| {
        let used = e.ebuilds.len();
        let gentoo_used = e.ebuilds.iter().filter(|e| e.overlay == "gentoo").count();
        let score = e
            .advisories
            .iter()
            .filter_map(|v| v.cvss.as_ref().map(|v| (v.score().value() * 1000.0) as i64))
            .max()
            .unwrap_or(i64::MIN);
        let prio = match e.advisories.is_empty() {
            false => 3,
            true => match e.yanked {
                Some(true) => 2,
                None => 1,
                Some(false) => 0,
            },
        };
        std::cmp::Reverse((prio, gentoo_used, score, used))
    });

    #[derive(serde::Serialize)]
    struct Output {
        status: Vec<CrateStatus>,
    }
    let outpath = OPTS.work_dir.join("status.json");
    log::debug!("Writing result to {}", outpath.to_string_lossy());
    let file = std::fs::File::create(outpath).context("Open output file")?;
    serde_json::to_writer_pretty(file, &Output { status: crates }).context("Write output")?;

    Ok(())
}

fn find_cargo_ebuilds<'a>(
    repo: &'a git2::Repository,
    overlay: &'a str,
    ret: &'a EbuildDeps,
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
                        parse(overlay, format!("{}{}", root, name), &content, ret);
                    }
                }
            }
        }
        git2::TreeWalkResult::Ok
    }
}

fn parse(overlay: &str, path: String, content: &str, ret: &EbuildDeps) {
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
        let crates = match re::split_pkgver(&path) {
            Some((pn, pv)) => crates
                .replace("${P}", &format!("{}-{}", pn, pv))
                .replace("${PV}", pv)
                .replace("${PN}", pn),
            None => {
                log::warn!(
                    "{}::{}: Strange ebuild name, can't get PN/PV",
                    overlay,
                    path
                );
                crates.to_string()
            }
        };
        let res = crates
            .split_whitespace()
            .filter_map(|spec_str| match cratespec_to_depinfo(spec_str) {
                Ok(di) => Some(di),
                Err(e) => {
                    log::warn!(
                        "{}::{}: Could not parse dependency {}:{}",
                        overlay,
                        path,
                        spec_str,
                        format_chain(&e),
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        log::debug!("{}::{}: deps: {:#?}", overlay, path, res);
        let overlay = overlay.to_string();
        ret.insert(Ebuild { overlay, path }, res);
    } else {
        log::warn!(
            "{}::{}: Could not get declaration of CRATES list",
            overlay,
            path,
        );
    }
}

fn cratespec_to_depinfo(spec_str: &str) -> Result<DepInfo> {
    let capt = re::DEPSPEC
        .captures(spec_str)
        .context("Does not match depspec regex")?;
    let name = Name::from_str(&capt[1]).context("Invalid name")?;
    let ver = Version::from_str(&capt[2]).context("Invalid version")?;
    Ok(DepInfo { name, ver })
}

fn fgo() -> Result<Vec<overlays::Overlay>> {
    Ok((|| -> Result<_> {
        let gentoo_meta = gitrepo::RepoRepo::on(&OPTS.work_dir.join("gentoo"))?;
        let head = gentoo_meta.up_or_head(GENTOO_META_REPO_ORIGIN, OPTS.offline)?;
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

fn cio() -> Result<YankingStatus> {
    let mut ret = HashMap::new();
    let repo = gitrepo::RepoRepo::on(&OPTS.work_dir.join("crates.io"))?;
    let head = repo.up_or_head(cargo::sources::registry::CRATES_IO_INDEX, OPTS.offline)?;
    head.peel_to_tree()?
        .walk(
            git2::TreeWalkMode::PreOrder,
            list_crates(repo.repo(), &mut ret),
        )
        .context("List crates in crates.io repo HEAD tree")?;
    Ok(ret)
}

// So there is this nice struct, cargo::sources::registry::RegistryPackage, which I'd have liked to
// use. It doesn't allow access to its members. :(
#[derive(Debug, serde::Deserialize, Clone)]
struct RegistryPackage {
    name: String,
    vers: String,
    yanked: bool,
}

type YankingStatus = HashMap<Name, HashMap<Version, bool>>;

fn list_crates<'a>(
    repo: &'a git2::Repository,
    ret: &'a mut YankingStatus,
) -> impl 'a + FnMut(&str, &git2::TreeEntry<'_>) -> git2::TreeWalkResult {
    move |folder, entry| {
        if Some(git2::ObjectType::Blob) == entry.kind() {
            if let Some(name) = entry.name() {
                if name == "config.json" && folder == "" {
                    return git2::TreeWalkResult::Skip; // Not that it matters
                }
                let content = entry.to_object(repo).unwrap();
                let content = content.as_blob().expect("Object blob").content();
                use std::io::BufRead;
                for (i, line) in content.lines().enumerate() {
                    match parse_spec(folder, name, line, ret) {
                        Ok(()) => (),
                        Err(e) => log::error!(
                            "Cannot parse crate info for {}{}:{}: {}",
                            folder,
                            name,
                            i + 1,
                            e
                        ),
                    }
                }
            } else {
                log::error!("Strange object without name in {}", folder);
            }
        }
        git2::TreeWalkResult::Ok
    }
}

fn parse_spec(
    folder: &str,
    filename: &str,
    spec: Result<String, std::io::Error>,
    ret: &mut YankingStatus,
) -> Result<()> {
    let spec = spec.context("Read line")?;
    let info = serde_json::from_str::<RegistryPackage>(&spec).context("Parse JSON line")?;

    let name = Name::from_str(&info.name).context("invalid name")?;
    let vers = Version::from_str(&info.vers).context("version spec unparseable")?;

    ret.entry(name)
        .or_insert_with(HashMap::new)
        .insert(vers, info.yanked);

    log::trace!("{}/{}: {:?}", folder, filename, info);

    Ok(())
}
